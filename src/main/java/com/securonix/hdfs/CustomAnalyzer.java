package com.securonix.hdfs;

import com.securonix.application.common.Constants;
import com.securonix.application.hadoop.HadoopConfigUtil;
import com.securonix.application.hibernate.tables.Configxml;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.hibernate.tables.Resourcegroups;
import com.securonix.application.hibernate.tables.RiskType;
import com.securonix.application.hibernate.util.DbUtil;
import com.securonix.application.impala.ImpalaDbUtil;
import com.securonix.application.policy.PolicyConstants;
import com.securonix.application.risk.dataAccess.uiUtil.RiskUtilImpl;
import com.securonix.kafkaclient.KafkaClient;
import static com.securonix.kafkaclient.KafkaClient.CF_ACTION_POLICY_UPDATED;
import static com.securonix.kafkaclient.KafkaClient.CF_ORIGINATOR_POLICY_ENGINE;
import com.securonix.rdd.SecuronixRDD;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import com.securonix.snyper.config.beans.KafkaConfigBean;
import com.securonix.snyper.policyengine.PolicyUtil;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.broadcast.Broadcast;
import org.apache.spark.storage.StorageLevel;

/**
 * Custom analyzer for historical data in HDFS. This is the entry point for the job.
 *
 * @author Securonix Inc.
 */
public class CustomAnalyzer {

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
        final InputStream stream = CustomAnalyzer.class.getClassLoader().getResourceAsStream("customanalyzer.properties");
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
        if (temp != null) {
            try {
                policyId = Long.parseLong(temp);
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
                policy = createPolicy(policyName, functionality, categoryId, riskThreatName, criticality, violator);
            } else {
                LOGGER.warn("POLICY ALREADY EXIST WITH THE NAME: {}", policyName);
            }
        }

        if (policy == null) {
            exit("Cannot proceed without a policy");
        }

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

        final Broadcast<QueryWrapper> wrapper = sc.broadcast(new QueryWrapper());
        final Broadcast<PolicyMaster> pm = sc.broadcast(policy);
        final JavaRDD<Long> rdd = sc.parallelize(rgIds).persist(StorageLevel.MEMORY_ONLY_SER());

        LOGGER.debug("About to start forming / executing queries ..");
        SecuronixRDD.flatMap(rdd, rgId -> {
            return formQueries(rgId);
        }).persist(StorageLevel.MEMORY_ONLY_SER()).foreachPartition(iterator -> {

            final QueryProcessor ap = ((QueryWrapper) wrapper.getValue()).getProcessor(hcb, pm.getValue());
            iterator.forEachRemaining(query -> {
                ap.process(query);
            });
        });

        LOGGER.info("Done!");
    }

    /**
     * Creates policy with the given inputs
     *
     * @param policyName Unique name for the policy
     * @param functionality Functionality type
     * @param categoryId Category Id
     * @param riskThreatName Threat name
     * @param criticality Criticality for the policy
     * @param violator Violation entity
     *
     * @return Policy object
     */
    private static PolicyMaster createPolicy(String policyName, String functionality, int categoryId, String riskThreatName, String criticality, String violator) {

        final long riskThreatId = RiskUtilImpl.getRiskThreatId(riskThreatName, "Medium", null);

        final Date currentTime = new Date();

        final PolicyMaster policy = new PolicyMaster();
        policy.setResourceGroupId(-1L);
        policy.setResourcetypeid(-1L);
        policy.setName(policyName);
        policy.setDescription("Created by custom spark job - " + currentTime);
        policy.setFunctionality(functionality);
        policy.setThreatname(riskThreatName);
        policy.setRiskthreatid(riskThreatId);
        policy.setLastUpdated(currentTime);

        policy.setType(PolicyConstants.TYPE_HDFS);
        policy.setCriticality(criticality);
        policy.setAnalyticstype("CUSTOM");
        policy.setTargetWorkflow("PolicyOutlierWorkflow");
        policy.setWeight(1l);

        policy.setCreatedBy("admin");
        policy.setUpdatedBy("admin");
        policy.setViolator(violator);

        policy.setDashboardDisplay(true);
        policy.setEnabled(true);

        final ArrayList<Integer> categoryIds = new ArrayList();
        policy.setCategoryid(categoryId);

        policy.setCategory(getCategoryName(categoryId));
        savePolicy(policy, categoryIds);

        LOGGER.info("POLICY CREATED WITH ID:{}", policy.getId());

        // inform Spark jobs to load the newly created policy
        KafkaClient.INSTANCE.publishControlFlag(policy.getId(), CF_ORIGINATOR_POLICY_ENGINE, CF_ACTION_POLICY_UPDATED);
        LOGGER.info("Control flag signalled to Kafka");

        return policy;
    }

    /**
     * Saves policy to the database (policy_master table)
     *
     * @param policy Policy to be saved
     * @param categoryIds Category Id for the policy
     */
    private static void savePolicy(final PolicyMaster policy, final ArrayList<Integer> categoryIds) {

        policy.setVerboseinfotemplate("Account ${accountname!\"ACCOUNTNAME\"} performed ${transactionstring1!\"ACTIVITY\"} from ipaddress ${ipaddress!\"UNKNOWN\"}");
        policy.setSignatureid(getSignatureId());

        final long riskTypeId = createRiskType(policy, "Policy");
        policy.setRiskTypeId(riskTypeId);
        DbUtil.saveTable(policy);
    }

    /**
     * Forms and returns signature Id for the policy
     *
     * @return Signature for the policy
     */
    private static String getSignatureId() {

        String currentsignatureId = getConfigXml(Constants.POLICY_SIGNATURE_ID);
        if (currentsignatureId == null || currentsignatureId.trim().isEmpty()) {
            currentsignatureId = "1000000";
        }

        Long signatureId = Long.parseLong(currentsignatureId);
        signatureId++;

        updateConfigXml(Constants.POLICY_SIGNATURE_ID, signatureId.toString());
        return signatureId.toString();
    }

    /**
     * Utility method to update config in the database
     *
     * @param xmlkey Key for the config
     * @param xmlvalue Configuration in XML format
     */
    private static void updateConfigXml(String xmlkey, String xmlvalue) {
        final Configxml configxml = new Configxml();
        configxml.setXmlkey(xmlkey);
        configxml.setXmlvalue(xmlvalue.trim());
        DbUtil.saveTable(configxml);
    }

    /**
     * Utility method to read and return configuration from the database for the given key
     *
     * @param xmlkey Configuration key
     *
     * @return Configuration for the given key
     */
    private static String getConfigXml(String xmlkey) {

        final Map<String, Object> parameters = new HashMap<>();
        parameters.put("xmlkey", xmlkey);

        final List<String> xmlValues = DbUtil.executeHQLQuery("SELECT xmlvalue FROM Configxml where xmlkey=:xmlkey", parameters, false);
        return xmlValues == null || xmlValues.isEmpty() ? null : xmlValues.get(0);
    }

    /**
     * Creates risk type for the policy
     *
     * @param policy Policy
     * @param source Source
     *
     * @return Risk type Id
     */
    private static long createRiskType(final PolicyMaster policy, final String source) {

        final RiskType type = new RiskType();
        type.setSource(source);
        type.setRiskname(policy.getName() + " Risk");
        DbUtil.saveTable(type);

        return type.getId();
    }

    /**
     * Reads and returns category name from the database for the given Id
     *
     * @param catid Category Id
     *
     * @return Name for the given category Id
     */
    private static String getCategoryName(Integer catid) {

        final Map<String, Object> parameters = new HashMap<>();
        parameters.put("catid", catid);

        final String query = "select categoryname from Policycategory where id=:catid";
        final List categorynames = DbUtil.executeHQLQuery(query, parameters, false);

        return categorynames.size() > 0 ? (String) categorynames.get(0) : "";
    }

    /**
     * Returns resource groups for the functionality
     *
     * @param functionality Functionality type
     *
     * @return List of resource group Ids for the given functionality type
     */
    private static List<Long> getResourceGroupsForFunctionality(final String functionality) {

        final List<Long> rgIds = new ArrayList();

        final List<Resourcegroups> rgList = DbUtil.executeHQLQuery("from Resourcegroups where functionality = '" + functionality + "'");
        rgList.forEach(rg -> {
            rgIds.add(rg.getId());
        });

        return rgIds;
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

        final String violationQuery = "select ipaddress, accountname, year, dayofyear, hour, minute from securonixresource" + rgId + "incoming where transactionstring1='Logon Failed' group by accountname, ipaddress, year, dayofyear, hour, minute having count(accountname) > 5";

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

                query = "select * from securonixresource" + rgId + "incoming where transactionstring1='Logon Failed' and accountname='" + account + "' and ipaddress='" + srcip + "' and year=" + year + " and dayofyear=" + dayofyear + " and hour =" + hour + " and minute=" + minute;
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
