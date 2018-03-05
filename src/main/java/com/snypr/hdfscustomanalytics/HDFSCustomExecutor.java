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
 * This class is used to perform custom analytics on HDFS data. The detected violations would be published to violations
 * topic.
 *
 * @author manishkumar
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
     * @param args Command line arguments
     *
     * @throws Exception
     */
    public static void main(String args[]) throws Exception {

        final Map<String, String> argumentsMap = SnyperUtil.extractArguments(args);

        if (!argumentsMap.containsKey("-pId")) {

            System.err.println("\nERROR: Insufficient input, policy Id is mandatory!");
            System.err.println("\nMandatory:");
            System.err.println("\t-pId\t\tPolicy Id");
            System.err.println("Optional:");

            System.err.println(); // a blank line!
            System.exit(-1);
        }

        // Get Hadoop configuration
        hcb = HadoopConfigUtil.getHadoopConfiguration();
        if (hcb == null) {
            System.err.println("Unable to obtain Hadoop configuration\n");
            System.exit(1);
        }

        // Get Kafka configuration from hadoop bean
        KafkaConfigBean kafkaConfigBean = hcb.getKafkaConfigBean();
        if (kafkaConfigBean == null) {
            System.err.println("\nERROR: Unable to obtain Kafka configuration\n");
            System.exit(-1);
        }

        // Get violation topic from kafka configuration
        final Set<String> topicsSet = new HashSet<>(Arrays.asList(kafkaConfigBean.getViolationTopic().split(",")));
        violationTopic = topicsSet.iterator().next();
        LOGGER.debug("Violation topic- {}", violationTopic);

        // Get policyId from VM arguments of job's run sricpt.
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
