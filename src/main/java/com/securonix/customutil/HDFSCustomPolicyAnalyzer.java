package com.securonix.customutil;

import com.securonix.application.hadoop.HadoopConfigUtil;
import com.securonix.kafkaclient.producers.EEOProducer;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.policy.PolicyConstants;
import com.securonix.hadoop.util.SnyperUtil;
import com.securonix.kafkaclient.producers.KafkaProducerFactory;
import com.securonix.snyper.config.beans.KafkaConfigBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import com.securonix.application.policy.PolicyUtil;
import com.securonix.application.risk.dataAccess.uiUtil.RiskUtilImpl;
import com.securonix.application.ui.uiUtil.SuspectActivitiesControllerUtil;
import java.util.List;

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
public class HDFSCustomPolicyAnalyzer {

    public static HadoopConfigBean hcb;
    public static EEOProducer eeoProducer;
    public static String violationTopic;

    private final static Logger LOGGER = LogManager.getLogger();

    public static PolicyMaster policy;
    final static Integer DEFAULT_POLICYID = 11;

    public static List<Long> functionlityEnabledRG = new ArrayList();

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

        if (!argumentsMap.containsKey("-policyName") || !argumentsMap.containsKey("-functionalityType") || !argumentsMap.containsKey("-categoryId")
                || !argumentsMap.containsKey("-riskThreatName")) {

            System.err.println("\nERROR: Insufficient input, policyName,functionalityType,categoryId,riskThreatName are mandatory!");
            System.err.println("\nMandatory:");
            System.err.println("\t-policyName\t\tPolicy Name");
            System.err.println("\t-functionalityType\t\tFunctionality Type");
            System.err.println("\t-categoryId\t\tCategory Id");
            System.err.println("\t-riskThreatName\t\tRisk Threat Name");
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

        // Start : Manish Kumar
        final String policyName = argumentsMap.get("-policyName");

        final String functionalityType = argumentsMap.get("-functionalityType");

        int categoryId = 0;

        try {
            categoryId = Integer.parseInt(argumentsMap.get("-categoryId"));
        } catch (NumberFormatException ex) {
            LOGGER.error("Error during categoryId extract", ex);
        }

        String policyCriticality;

        if (argumentsMap.containsKey("-criticality")) {
            policyCriticality = argumentsMap.get("-criticality");
        } else {
            policyCriticality = "Low";
        }

        String userName;
        if (argumentsMap.containsKey("-userName")) {
            userName = argumentsMap.get("-userName");
        } else {
            userName = "admin";
        }

        String violatorEntity;

        if (argumentsMap.containsKey("-violatorEntity")) {
            violatorEntity = argumentsMap.get("-violatorEntity");
        } else {
            violatorEntity = "Activityaccount";
        }

        final String riskThreatName = argumentsMap.get("-riskThreatName");

        long riskThreatId = RiskUtilImpl.getRiskThreatId(riskThreatName, "Medium", null);

        policy = new PolicyMaster();
        policy.setName(policyName);
        policy.setDescription(policyName + " - " + new Date());
        policy.setFunctionality(functionalityType);
        policy.setThreatname(riskThreatName);
        policy.setRiskthreatid(riskThreatId);

        policy.setType(PolicyConstants.TYPE_HDFS);
        policy.setCriticality(policyCriticality);
        policy.setAnalyticstype("CUSTOM");
        policy.setTargetWorkflow("PolicyOutlierWorkflow");
        policy.setWeight(1l);

        policy.setCreatedBy(userName);
        policy.setUpdatedBy(userName);
        policy.setViolator(violatorEntity);
        policy.setViolation(violatorEntity);

        policy.setDashboardDisplay(true);
        policy.setEnabled(true);

        ArrayList<Integer> categoryIds = new ArrayList();

        policy.setCategoryid(categoryId);

        policy.setCategory(SuspectActivitiesControllerUtil.getCategoryname(categoryId));
        PolicyUtil.savePolicy(policy, true, categoryIds);

        functionlityEnabledRG = HDFSCustomUtil.getFunctionalityEnabledResourceGroup(functionalityType);

        if (functionlityEnabledRG.isEmpty()) {
            LOGGER.warn("Functionlity [" + functionalityType + "] enabled Resourcegroup is not avialable");
            System.exit(-1);

        }

        Properties props = new Properties();
        props.put("source", HadoopConfigBean.KAFKA_SOURCE.CLUSTER);

        // Get Kafka Publisher to publish data into Violation topic
        eeoProducer = (EEOProducer) KafkaProducerFactory.INSTANCE.getProducer(KafkaProducerFactory.TYPE_OF_MESSAGE.EEO, kafkaConfigBean, props);

        // Start processing for custom analytics 
        HDFSCustomUtil.executeManualCustomPolicy();
    }

}
