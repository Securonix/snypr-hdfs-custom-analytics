package com.securonix.customanalyzer;

import com.securonix.application.hadoop.HadoopConfigUtil;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.impala.ImpalaDbUtil;
import com.securonix.kafkaclient.KafkaClient;
import com.securonix.rdd.SecuronixRDD;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import com.securonix.snyper.config.beans.KafkaConfigBean;
import com.securonix.snyper.policyengine.PolicyUtil;
import static com.securonix.customanalyzer.CustomAnalyzerHelper.createPolicy;
import static com.securonix.customanalyzer.CustomAnalyzerHelper.getResourceGroupsForFunctionality;
import static com.securonix.customanalyzer.CustomAnalyzerHelper.readViolationInfoProperties;
import com.securonix.customanalyzer.analytics.CustomAnalyzer1;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.broadcast.Broadcast;
import org.apache.spark.storage.StorageLevel;

/**
 * This CustomAnalyzerSparkJob class is the entry point for the Spark Job. It extracts the information for Hadoop
 * components. It reads the customanalyzer.properties file that has policy information. The violations are published to
 * the violation topic for downstream risk scoring.
 *
 * @see <code>publish</code> method in the <code>com.securonix.kafkaclient.producers.EEOProducer</code> module
 * @author ManishKumar
 * @version 1.0
 * @since 2017-03-31
 */
public class CustomAnalyzerSparkJob {

    /**
     * Logger for the class
     */
    private final static Logger LOGGER = LogManager.getLogger();

    /**
     * Entry point for the job. Reads configuration from the external file, creates / loads policy, forms queries and
     * fire them on the executors.
     *
     * @param args Command line arguments
     *
     * @throws Exception in case of an error initializing the job
     */
    public static void main(String args[]) throws Exception {

        // get the configuration from database, for connecting to Hadoop components
        final HadoopConfigBean hcb = HadoopConfigUtil.getHadoopConfiguration();
        if (hcb == null) {
            exit("Unable to obtain Hadoop configuration");
        }
        LOGGER.debug("Hadoop config obtained");

        // retrieve Kafka configuration for publishing flags and messages to topics
        final KafkaConfigBean kafkaConfigBean = hcb.getKafkaConfigBean();
        if (kafkaConfigBean == null) {
            exit("\nERROR: Unable to obtain Kafka configuration");
        }

        /*
         * Need to initialize Kafka client for publishing flags and messages to topics. Kafka source indicates the 
         * environment on which this code is being executed, it's used to read ans set SSL properties, if configured.
         */
        KafkaClient.INSTANCE.initialize(kafkaConfigBean, false, HadoopConfigBean.KAFKA_SOURCE.CLUSTER);
        LOGGER.debug("Kafka config obtained and Kafka client intialized");

        // read policy config from the properties file
        final InputStream stream = CustomAnalyzerSparkJob.class.getClassLoader().getResourceAsStream("customanalyzer.properties");
        LOGGER.debug("Custom properties loaded? {}", (stream != null));

        if (stream == null) {
            exit("Unable to read config from customanalyzer.properties file!");
        }

        final Properties props = new Properties();
        props.load(stream);

        long policyId;
        PolicyMaster policy = null;

        String policyName;
        String functionality;
        int categoryId = -1;
        String riskThreatName;
        String criticality;
        String violator;

        String temp = props.getProperty("policyId");
        if (temp != null && temp.trim().length() != 0) {
            try {
                policyId = Long.parseLong(temp.trim());
                if (policyId > 0) {
                    policy = PolicyUtil.getPolicy(policyId);
                } else {
                    exit("Invalid policy Id:" + policyId);
                }
            } catch (NumberFormatException ex) {
                exit("Error parsing policy Id");
            }
        } else {

            // attempt to create a policy
            policyName = props.getProperty("policyName");

            // Mandatory chcek for policy name
            if (policyName == null || policyName.trim().isEmpty()) {
                exit("PolicyName is not configured in customanalyzer.properties file");
            }

            functionality = props.getProperty("functionality");
            try {
                categoryId = Integer.parseInt(props.getProperty("categoryId"));
            } catch (Exception ex) {
                exit("Error parsing category Id");
            }

            riskThreatName = props.getProperty("riskThreatName");
            criticality = props.getProperty("criticality", "Low");
            if (criticality.trim().isEmpty()) {
                criticality = "Low";
            }
            violator = props.getProperty("violationEntity", "Activityaccount");

            // policy name must be unique, check if the policy already exist for the given name
            policy = PolicyUtil.getPolicyForPolicyName(policyName);
            if (policy == null) {

                // Mandatory check for riskThreatName and functionality
                if (riskThreatName == null || riskThreatName.trim().isEmpty()) {
                    exit("riskThreatName is not configured in customanalyzer.properties file");
                }

                if (functionality == null || functionality.trim().isEmpty()) {
                    exit("functionality is not configured in customanalyzer.properties file");
                }

                policy = createPolicy(policyName, functionality, categoryId, riskThreatName, criticality, violator, readViolationInfoProperties(props));

            } else {
                LOGGER.warn("POLICY ALREADY EXIST WITH THE NAME: {}", policyName);
            }
        }

        if (policy == null) {
            exit("Cannot proceed without a policy");
        }

        // Applies analytics to specific Resource Group or Resource Groups matching functionality provided in customanalyzer.properties file
        List<Long> rgIds;
        if (policy.getResourceGroupId() == -1) {
            rgIds = getResourceGroupsForFunctionality(policy.getFunctionality());
        } else {
            rgIds = new ArrayList<>();
            rgIds.add(policy.getResourceGroupId());
        }

        LOGGER.debug("RGIds # {}", rgIds.size());

        final SparkConf conf = new SparkConf();
        final JavaSparkContext sc = new JavaSparkContext(conf);
        final int numExecutors = sc.getConf().getInt("spark.executor.instances", 19);
        LOGGER.debug("Executors # {}", numExecutors);

        final Broadcast<QueryWrapper> wrapper = sc.broadcast(new QueryWrapper());
        final Broadcast<PolicyMaster> pm = sc.broadcast(policy);
        final JavaRDD<Long> rdd = sc.parallelize(rgIds).persist(StorageLevel.MEMORY_ONLY_SER());

        LOGGER.debug("About to start forming / executing queries ..");
        // SecuronixRDD is a wrapper for ensuring compatibility with Spark 1.6.x & Spark 2.x
        JavaRDD<String> persist = SecuronixRDD.flatMap(rdd, rgId -> {
            // Query HDFS to extract events/violations and return a list of queries that can be executed in parallel across executors to extract events
            // Alternatively, you can write a query against HDFS to extract events and iterate through events to perform analytics
            // In below example, formQueries returns back a list of queries for each violation
            return CustomAnalyzer1.formQueries(rgId);
        }).repartition(numExecutors).persist(StorageLevel.MEMORY_ONLY_SER());

        persist.foreachPartition(iterator -> {
            // Initializes the Kafka producer to publish to Violation Topic
            final QueryProcessor ap = ((QueryWrapper) wrapper.getValue()).getProcessor(hcb, pm.getValue());
            // Iterate through list of queries and execute on each partition
            LOGGER.debug("New Partition:");

            iterator.forEachRemaining(query -> {
                // Execute query against HDFS using Impala

                LOGGER.debug("Query:{}", query);
                ap.process(query);
            });
        });

        LOGGER.info("Done!");
    }

    /**
     * Forms the queries based on resource group Id
     *
     * @param rgId Resource group Id
     * @return List of queries formed for the given resource group
     */
    private static List<String> formQueries(final long rgId) {

        LOGGER.debug("Forming queries for RgId: {}", rgId);
        final List<String> queries = new ArrayList<>();

        final String violationQuery = "select ipaddress, accountname, year, dayofyear, hour, minute from activity" + rgId + "incoming where message='Logon Failed' group by accountname, ipaddress, year, dayofyear, hour, minute having count(accountname) > 5";

        // PERFORM ANALYTICS HERE
        List<HashMap<String, Object>> violationEvents = null;
        try {
            violationEvents = ImpalaDbUtil.executeQuery(violationQuery);
        } catch (Exception ex) {
            LOGGER.error("Error getting results from HDFS", ex);
        }

        LOGGER.debug("Base query violation count # {}", (violationEvents == null ? 0 : violationEvents.size()));
        if (violationEvents != null && !violationEvents.isEmpty()) {

            String query;
            for (HashMap<String, Object> violationEvent : violationEvents) {

                String account = (String) violationEvent.get("accountname");
                String srcip = (String) violationEvent.get("ipaddress");
                String year = (String) violationEvent.get("year");
                String dayofyear = (String) violationEvent.get("dayofyear");
                String hour = (String) violationEvent.get("hour");
                String minute = (String) violationEvent.get("minute");

                query = "select * from activity" + rgId + "incoming where message='Logon Failed' and accountname='" + account + "' and ipaddress='" + srcip + "' and year=" + year + " and dayofyear=" + dayofyear + " and hour =" + hour + " and minute=" + minute;
                queries.add(query);
            }

        } else {
            LOGGER.info("No Violation found");
        }

        LOGGER.debug("Returning queries # {}", queries.size());
        return queries;
    }

    /**
     * Terminates the job with the error message
     *
     * @param error Error message
     */
    private static void exit(final String error) {
        System.err.println(error + "\n");
        System.exit(-1);
    }
}
