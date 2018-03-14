package com.securonix.scala.customanalyzer
import com.securonix.application.common.CommonUtility;
import com.securonix.application.common.JAXBUtilImpl;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.impala.ImpalaDbUtil;
import com.securonix.application.policy.PolicyConstants;
import com.securonix.application.suspect.ViolationInfoBuildUtil;
import com.securonix.kafkaclient.producers.EEOProducer;
import com.securonix.kafkaclient.producers.KafkaProducerFactory;
import com.securonix.snyper.common.EnrichedEventObject;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import com.securonix.snyper.config.beans.KafkaConfigBean;
import com.securonix.snyper.policy.beans.ViolationDisplayConfigBean;
import com.securonix.snyper.policy.beans.violations.Violation;
import com.securonix.snyper.util.DateUtil;
import com.securonix.snyper.violationinfo.beans.VerboseInfoDetails;
import com.securonix.snyper.violationinfo.beans.ViolationDetails;
import com.securonix.snyper.violationinfo.beans.ViolationDetailsFactory;
import com.securonix.snyper.violationinfo.beans.ViolationDetailsTree;
import com.securonix.snyper.violationinfo.beans.ViolationInfo;
import com.securonix.snyper.violationinfo.beans.ViolationInfoConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.securonix.application.policy.PolicyConstants.BATCH_SIZE;
import scala.collection.JavaConversions._
import java.lang.Long
import com.securonix.customutil.EEOUtil
class QueryProcessor (val hcb: HadoopConfigBean, val policy: PolicyMaster) {
  
   /**
   * Kafka producer to publish violations to the topic
   */
  var eeoProducer: EEOProducer = null;
  /**
   * Topic to which the violations are to be published
   */
  var violationTopic: String = null;

  val LOGGER: Logger = LogManager.getLogger();
  val kcb: KafkaConfigBean = hcb.getKafkaConfigBean();
  this.violationTopic = kcb.getViolationTopic
  

  val props: Properties = new Properties();
  props.put("source", HadoopConfigBean.KAFKA_SOURCE.CLUSTER);

  eeoProducer = KafkaProducerFactory.INSTANCE.getProducer(KafkaProducerFactory.TYPE_OF_MESSAGE.EEO, kcb, props).asInstanceOf[EEOProducer];

  LOGGER.info("Query processor initialized! and topic Name is:"+this.violationTopic);

  /**
   * Logger for the class
   */

  //Modified   
  val vInfoConfig: HashMap[Long, Tuple2[ViolationDisplayConfigBean, List[String]]] = new HashMap();

 /**
   * Policy configuration
   */
  def process(query: String) {

    var events: List[HashMap[String, Object]] = null;
    var resultCount: Long = 0;
    var offset: Int = 0;

    var recordsAvailable: Boolean = true;
    while (recordsAvailable) {
      LOGGER.info(s"Querying with Offset:${offset} Max:${BATCH_SIZE} Q:${query}")

      try {
        events = ImpalaDbUtil.executeImapalaQueryByEventTime(query, offset, BATCH_SIZE);
      } catch {
        case e: NumberFormatException =>
          {
            LOGGER.error("Error getting results from HDFS", e);
          }

      }

      if (events == null || events.isEmpty()) {
        LOGGER.warn("No response from HDFS!");
        recordsAvailable = false;

      } else {
        resultCount = events.size();
        LOGGER.info(s"Total documents:${resultCount} Returned:${events.size()}")

        // process hdfs details and collect violations data
        collectViolations(events.iterator());
                              
        if (recordsAvailable == (resultCount >= BATCH_SIZE)) {
          offset += BATCH_SIZE;          
        } else {
          LOGGER.info("NO MORE RESULTS FROM HDFS!");
          recordsAvailable = false;
        }
      }

    }

  }
  
  
def collectViolations(iterator: Iterator[HashMap[String, Object]]) {
    LOGGER.debug("Updating violations ..");

    val violationList: List[EnrichedEventObject] = new ArrayList();
    // eeo object will have complete event details (along-with violations details) 
    var eeo: EnrichedEventObject = null;

    var vi: ViolationInfo = null;
    var v: Violation = null;
    var vdDetails: Map[Long, Map[String, ViolationDetails]] = null;
    var violations: List[Violation] = null;
    val policyId: Long = policy.getId();
    val policyName: String = policy.getName();

    val violator: String = policy.getViolator
    val riskthreatid: Long = policy.getRiskthreatid
    val threatname: String = policy.getThreatname
    val riskTypeId: Long = policy.getRiskTypeId
    val categoryid: Int = policy.getCategoryid
    val category: String = policy.getCategory
    val riskScore: Double = PolicyConstants.CRITICALITY_MAP.get(policy.getCriticality())

    val violationdisplayconfig: String = policy.getViolationdisplayconfig();

    if (violationdisplayconfig != null && !violationdisplayconfig.isEmpty()) {
      val displayConfigBeans: List[ViolationDisplayConfigBean] = JAXBUtilImpl.xmlToPojos(violationdisplayconfig, classOf[ViolationDisplayConfigBean]);

      var displayConfigBean: ViolationDisplayConfigBean = null
      if (!displayConfigBeans.isEmpty()) {
        displayConfigBean = displayConfigBeans.get(0)
      }
      var parseTemplate: List[String] = null

      if ((policy.getVerboseinfotemplate() != null && !policy.getVerboseinfotemplate().isEmpty())) {
        parseTemplate = CommonUtility.parseTemplate(policy.getVerboseinfotemplate())
      } else {
        parseTemplate = new ArrayList()
      }
      vInfoConfig.put(policyId, new Tuple2(displayConfigBean, parseTemplate));
    }

    val params: Map[String, Object] = new HashMap();
    LOGGER.info("About to form EEOs ..");
    while (iterator.hasNext()) {

      eeo = new EnrichedEventObject();

      // populate eeo object with the help of HDFS details
      EEOUtil.populateEEO(iterator.next(), eeo);

      //Modified
      violations = new ArrayList()
      eeo.setViolations(violations);
      v = new Violation(policyId, policyName)
      violations.add(v);

      v.setViolator(violator);
      v.setRiskThreatId(riskthreatid);
      v.setRiskThreatName(threatname);
      v.setRiskTypeId(riskTypeId);
      v.setCategoryId(categoryid);
      v.setCategory(category);

      // Generated Violation Info
      vdDetails = new HashMap();
      vi = new ViolationInfo();
      //Deafult Violation info Forms a tree Structure
      var groupingAttribute: String = null;
      var lvl2Attribute: String = null;
      var metaDataList: List[String] = null;
      var level2MetaDataList: List[String] = null;

      var verboseKeys: List[String] = null;

      if (vInfoConfig != null && vInfoConfig.containsKey(policyId)) {
        var vInfoDisplayConfig: Tuple2[ViolationDisplayConfigBean, List[String]] = vInfoConfig.get(policyId);

        if (vInfoConfig.get(policyId)._1 != null) {
          if (vInfoDisplayConfig._1.getDisplayAttributes() != null && !vInfoDisplayConfig._1.getDisplayAttributes().isEmpty()) {
            groupingAttribute = vInfoDisplayConfig._1.getDisplayAttributes().get(0);
          }
          lvl2Attribute = vInfoDisplayConfig._1.getLevel2Attributes();
          metaDataList = vInfoDisplayConfig._1.getMetadataAttributes();
          level2MetaDataList = vInfoDisplayConfig._1.getLevel2MetaDataAttr();
        }
        if (vInfoConfig.get(policyId)._2 != null) {
          verboseKeys = vInfoDisplayConfig._2
        }
      }

      val params: Map[String, Object] = new HashMap();
      params.put(ViolationInfoConstants.FUNCTION_TYPE, ViolationInfoConstants.TREEPOLICYTYPE);
      params.put(ViolationDetailsTree.PARAMS.GROUP_ATTRIBUTE.name(), groupingAttribute);
      params.put(ViolationDetailsTree.PARAMS.LVL2_ATTRIBUTE.name(), lvl2Attribute);
      params.put(ViolationDetailsTree.PARAMS.METADATA_LIST.name(), metaDataList);
      params.put(ViolationDetailsTree.PARAMS.LVL2_METADATA.name(), level2MetaDataList);

      val buildViolationDetailsFromViolation: Map[String, ViolationDetails] = ViolationDetailsFactory.getViolationDetails(ViolationInfoConstants.TREEPOLICYTYPE, eeo, params);

      if (buildViolationDetailsFromViolation != null) {
        //Modified
        var tTimezone: String = null;
        if (eeo.getTenantTz != null) {
          tTimezone = eeo.getTenantTz
        } else {
          tTimezone = "GMT"
        }
        vdDetails.put(DateUtil.getScrubbedEpochTimeForDay(tTimezone, v.getGenerationTime()), buildViolationDetailsFromViolation);
      }
      vi.setViolationDetails(vdDetails);

      val verboseDetails: HashMap[Long, Map[String, VerboseInfoDetails]] = new HashMap();
      //Modified
      var tTimezone: String = null;
      if (eeo.getTenantTz != null) {
        tTimezone = eeo.getTenantTz
      } else {
        tTimezone = "GMT"
      }
      verboseDetails.put(DateUtil.getScrubbedEpochTimeForDay(tTimezone, v.getGenerationTime()), ViolationInfoBuildUtil.buildVerbosKeyValueMap(eeo, verboseKeys));

      vi.setVerbosKeyValueMap(verboseDetails);

      v.setViolationInfo(vi);

      v.setRiskScore(riskScore);

      // eeo object is added to violationList
      violationList.add(eeo);
    }
    LOGGER.debug(s"Violations found :${violationList.size()}")

    if (!violationList.isEmpty()) {
      eeoProducer.publish(violationList, violationTopic);
      LOGGER.debug(s"Scala:Violations published :${violationList.size()}")
      violationList.clear();
    }
  }
  
}