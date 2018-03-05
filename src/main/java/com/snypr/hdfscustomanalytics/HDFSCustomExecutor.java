package com.snypr.hdfscustomanalytics;

import com.securonix.application.hadoop.HadoopConfigUtil;
import com.securonix.kafkaclient.producers.EEOProducer;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.hadoop.util.SnyperUtil;
import com.securonix.kafkaclient.producers.KafkaProducerFactory;
import com.securonix.snyper.config.beans.KafkaConfigBean;
import com.securonix.snyper.policyengine.PolicyUtil;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * <h1>HDFS Custom Spark Analyzer for SNYPR</h1>
 * The HDFSCustomExecutor class provides an example to write a Spark Application
 * that can be launched within the SNYPR cluster to enable users to write their
 * own analytics. This HDFSCustomExecutor class execute custom query and detect
 * violations from The HDFS. The violations are published to the violation topic
 * for downstream risk scoring.. The violations are published to the violation
 * topic for downstream risk scoring.
 *
 * @author ManishKumar
 * @version 1.0
 * @since 2017-03-31
 */
public class HDFSCustomExecutor {

    public static HadoopConfigBean hcb;
    public static EEOProducer eeoProducer;
    public static String violationTopic;

    private final static Logger LOGGER = LogManager.getLogger();

    public static PolicyMaster policy;

    /**
     * Entry point for the job, expect policy Id
     *
     * @param args Arguments passed to the main method by the Spark Submit
     * @throws java.lang.Exception
     * @author ManishKumar
     * @version 1.0
     * @since 2017-03-31
     */
    public static void main(String args[]) throws Exception {

        // Extract arguments passed to Main Method
        final Map<String, String> argumentsMap = SnyperUtil.extractArguments(args);

        if (!argumentsMap.containsKey("-pId")) {

            System.err.println("\nERROR: Insufficient input, policy Id is mandatory!");
            System.err.println("\nMandatory:");
            System.err.println("\t-pId\t\tPolicy Id");
            System.err.println("Optional:");

            System.err.println();
            System.exit(-1);
        }

        // Read Hadoop Settings from SNYPR database. This has all connection details for various hadoop components including Kafka & HBase
        //If Hadoop settings are not available, Spark job will fail to start up.
        hcb = HadoopConfigUtil.getHadoopConfiguration();
        if (hcb == null) {
            System.err.println("Unable to obtain Hadoop configuration\n");
            System.exit(1);
        }

        // Extract Kafka connection details
         //If Kafka settings are not available, Spark job will fail to start up.
        KafkaConfigBean kafkaConfigBean = hcb.getKafkaConfigBean();
        if (kafkaConfigBean == null) {
            System.err.println("\nERROR: Unable to obtain Kafka configuration\n");
            System.exit(-1);
        }

        // Extract Violation Topic from Kafka connection details.
        final Set<String> topicsSet = new HashSet<>(Arrays.asList(kafkaConfigBean.getViolationTopic().split(",")));
        violationTopic = topicsSet.iterator().next();
        LOGGER.debug("Violation topic- {}", violationTopic);

        // Get policyId from VM arguments of job's run sricpt.
        //If policyId is not available, Spark job will fail to start up.
        long policyId = 0;
        try {
            policyId = Integer.parseInt(argumentsMap.get("-pId"));
        } catch (NumberFormatException ex) {
            System.err.println("Unable to parse policy Id\n");
            System.exit(1);
        }

        policy = PolicyUtil.getPolicy(policyId);
        if (policy == null) {
            System.err.println("Unable to obtain policy configuration for Id:" + policyId);
            System.exit(-1);
        }

        Properties props = new Properties();
        props.put("source", HadoopConfigBean.KAFKA_SOURCE.CLUSTER);

        // Get Kafka Publisher to publish data into Violation topic
        eeoProducer = (EEOProducer) KafkaProducerFactory.INSTANCE.getProducer(KafkaProducerFactory.TYPE_OF_MESSAGE.EEO, kafkaConfigBean, props);

        // Start processing for custom analytics 
        HDFSCustomUtil.executeCustomPolicy(policy);
    }

}
