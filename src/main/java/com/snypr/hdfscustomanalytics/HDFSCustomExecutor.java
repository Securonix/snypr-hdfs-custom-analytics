/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.snypr.hdfscustomanalytics;

import com.securonix.application.hadoop.HadoopConfigUtil;
import com.securonix.hadoop.util.OpsLogger;
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
 * This class is used to perform custom analytics on HDFS data. 
 * and detected violations get stored into Violations topic. 
 *
 * @author manishkumar
 */
public class HDFSCustomExecutor {

    public static HadoopConfigBean hcb;
    public static EEOProducer eeoProducer;
    public static String violationTopic;

    private final static Logger LOGGER = LogManager.getLogger();

    public static PolicyMaster policy;
   
    /*
    This main method is entry point of custom job to perform custom analytics on HDFS data
    */
    public static void main(String args[]) throws Exception {

        final Map<String, String> argumentsMap = SnyperUtil.extractArguments(args);

        if (!argumentsMap.containsKey("-cg") || !argumentsMap.containsKey("-d")) {

            System.err.println("\nERROR: Insufficient input, consumer group and duration are mandatory!");
            System.err.println("\nMandatory:");
            System.err.println("\t-cg\t\tConsumer group");
            System.err.println("\t-d\t\tDuration (in seconds)");
            System.err.println("Optional:");
            System.err.println("\t-or\t\tAuto Offset Reset [smallest|largest]");
            System.err.println("\t-mrpp\t\tMax rate per partition");

            System.err.println(); // a blank line!
            System.exit(-1);
        }     

        // Get Hadoop configuration
        
        hcb = HadoopConfigUtil.getHadoopConfiguration();
        if (hcb == null) {
            System.err.println("Unable to obtain Hadoop configuration\n");
            OpsLogger.log(OpsLogger.SOURCE.IEE, OpsLogger.SEVERITY.HIGH, "ERROR: Unable to obtain Hadoop configuration");
            System.exit(1);
        }

        OpsLogger.log(OpsLogger.SOURCE.IEE, "Hadoop configuration obtained!");
        
        
        // Get Kafka configuration from hadoop bean

        KafkaConfigBean kafkaConfigBean = hcb.getKafkaConfigBean();
        if (kafkaConfigBean == null) {
            System.err.println("\nERROR: Unable to obtain Kafka configuration\n");
            OpsLogger.log(OpsLogger.SOURCE.IEE, OpsLogger.SEVERITY.HIGH, "Unable to obtain Kafka configuration");
            System.exit(-1);
        }
        OpsLogger.log(OpsLogger.SOURCE.IEE, "Kafka configuration obtained!");
        
        // Get violation topic from kafka configuration

        final Set<String> topicsSet = new HashSet<>(Arrays.asList(kafkaConfigBean.getViolationTopic().split(",")));
        if (violationTopic == null || violationTopic.isEmpty()) {
            violationTopic = topicsSet.iterator().next();
        }
        LOGGER.debug("Violation topic- {}", violationTopic);
        
        // Get policyId from VM arguments of job's run sricpt.
        
        long policyId = 0;
        if (argumentsMap.containsKey("-pmId")) {
            try {
                policyId = Long.parseLong(argumentsMap.get("-pmId"));
            } catch (NumberFormatException ex) {
                System.err.println("Unable to obtain PolicyID configuration\n");
                OpsLogger.log(OpsLogger.SOURCE.IEE, OpsLogger.SEVERITY.HIGH, "ERROR: Unable to obtain PolicyID configuration");
                System.exit(1);

            }
        }
        
        // Get required Policy object.

        policy = PolicyUtil.getPolicy(policyId);

        Properties props = new Properties();
        props.put("source", HadoopConfigBean.KAFKA_SOURCE.CLUSTER);
        
        // Get Kafka Publisher to publish data into Violation topic

        eeoProducer = (EEOProducer) KafkaProducerFactory.INSTANCE.getProducer(KafkaProducerFactory.TYPE_OF_MESSAGE.EEO, kafkaConfigBean, props);

        // Start processing for custom analytics 
        
        HDFSCustomUtil.executeCustomPolicy(policy);
    }

}
