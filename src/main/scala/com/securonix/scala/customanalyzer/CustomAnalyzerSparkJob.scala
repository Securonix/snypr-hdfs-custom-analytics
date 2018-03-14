package com.securonix.scala.customanalyzer
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.apache.spark.broadcast.Broadcast;
import org.apache.spark.storage.StorageLevel;

import org.apache.spark.SparkContext

import scala.collection.JavaConversions._
import com.securonix.rdd.SecuronixRDD

import com.securonix.snyper.policy.beans.ViolationDisplayConfigBean

import com.securonix.customanalyzer.analytics.CustomAnalyzer1
import com.securonix.customanalyzer.CustomAnalyzerHelper

object CustomAnalyzerSparkJob {
  
  /**
   * Logger for the class
   */
  private val LOGGER: Logger = LogManager.getLogger();

  /**
   * Entry point for the job. Reads configuration from the external file, creates / loads policy, forms queries and
   * fire them on the executors.
   *
   * @param args Command line arguments
   *
   * @throws Exception in case of an error initializing the job
   */
  def main(args: Array[String]): Unit = {

    // get the configuration from database, for connecting to Hadoop components
    val hcb: HadoopConfigBean = HadoopConfigUtil.getHadoopConfiguration();
    if (hcb == null) {
      exit("Unable to obtain Hadoop configuration")

    }
    LOGGER.debug("Hadoop config obtained");

    // retrieve Kafka configuration for publishing flags and messages to topics
    val kafkaConfigBean: KafkaConfigBean = hcb.getKafkaConfigBean();
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
    val stream: InputStream = CustomAnalyzerSparkJob.getClass.getClassLoader().getResourceAsStream("customanalyzer.properties");
    val isStreamEmpty = stream != null
    LOGGER.debug("Custom properties loaded? " + isStreamEmpty)

    if (stream == null) {
      exit("Unable to read config from customanalyzer.properties file!");
    }

    val props: Properties = new Properties();
    props.load(stream);

    var policyId: Long = 0
    var policy: PolicyMaster = null

    var policyName: String = null
    var functionality: String = null
    var categoryId: Int = -1
    var riskThreatName: String = null
    var criticality: String = null
    var violator: String = null

    var temp: String = props.getProperty("policyId");

    if (temp != null) {
      try {
        policyId = temp.toLong
        if (policyId > 0) {
          policy = PolicyUtil.getPolicy(policyId);
        } else {
          exit("Invalid policy Id:" + policyId);
        }
      } catch {
        case e: NumberFormatException =>
          {
            exit("Error parsing policy Id");
          }

      }
    } else {

      // attempt to create a policy
      policyName = props.getProperty("policyName");
      functionality = props.getProperty("functionality");
      try {
        categoryId = Integer.parseInt(props.getProperty("categoryId"));
      } catch {
        case e: Exception =>
          {
            exit("Error parsing policy Id");
          }

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
        policy = CustomAnalyzerHelper.createPolicy(policyName, functionality, categoryId, riskThreatName, criticality, violator, CustomAnalyzerHelper.readViolationInfoProperties(props));        
      } else {
        LOGGER.warn("POLICY ALREADY EXIST WITH THE NAME: {}", policyName);
      }
    }

    if (policy == null) {
      exit("Cannot proceed without a policy");
    }

    var rgIds: List[Long] = null;
    if (policy.getResourceGroupId() == -1) {

      rgIds = CustomAnalyzerHelper.getResourceGroupsForFunctionality(policy.getFunctionality()).asInstanceOf[List[Long]];

    } else {
      rgIds = new ArrayList();
      rgIds.add(policy.getResourceGroupId());
    }

    LOGGER.debug("RGIds # " + rgIds.size());
    val conf: SparkConf = new SparkConf();
    val sc: SparkContext = new SparkContext(conf)

    val wrapper: Broadcast[QueryWrapper] = sc.broadcast(new QueryWrapper);
    val pm: Broadcast[PolicyMaster] = sc.broadcast(policy);
    val rdd = sc.parallelize(rgIds).persist(StorageLevel.MEMORY_ONLY_SER);
   val  numExecutors:Int = sc.getConf.getInt("spark.executor.instances", 19);  
    LOGGER.debug(s"Executors :${numExecutors}")
    
    LOGGER.debug("About to start forming / executing queries ..");
    rdd.flatMap(x => CustomAnalyzer1.formQueries(x)).persist(StorageLevel.MEMORY_ONLY_SER).repartition(numExecutors).foreachPartition((iterator: Iterator[String]) => {
      val ap:QueryProcessor = (wrapper.value).getProcessor(hcb, pm.value);
      iterator.foreach((query: String) => {
        ap.process(query);
      })

    })
    
    LOGGER.info("Done!");

  }

    /**
     * Terminates the job with the error message
     *
     * @param error Error message
     */
    def   exit( error:String) {
        System.err.println(error + "\n");
        System.exit(-1);
    }
}