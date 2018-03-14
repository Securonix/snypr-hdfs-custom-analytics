package com.securonix.customanalyzer;

import com.securonix.application.common.CommonUtility;
import com.securonix.application.common.JAXBUtilImpl;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.impala.ImpalaDbUtil;
import com.securonix.application.policy.PolicyConstants;
import static com.securonix.application.policy.PolicyConstants.BATCH_SIZE;
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
import com.securonix.customutil.EEOUtil;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import scala.Tuple2;

/**
 * Fires query against HDFS, collects and publishes violations to the Kafka topic
 *
 * @author Securonix Inc.
 */
public class QueryProcessor {

    /**
     * Logger for the class
     */
    private final static Logger LOGGER = LogManager.getLogger();
    /**
     * Kafka producer to publish violations to the topic
     */
    private final EEOProducer eeoProducer;
    /**
     * Topic to which the violations are to be published
     */
    private final String violationTopic;
    /**
     * Policy configuration
     */
    private final PolicyMaster policy;

    /**
     * Accepts Hadoop and policy configurations, and initializes Kafka producer for publishing violations to the topic
     *
     * @param hcb Hadoop configuration
     * @param policy Policy configuration
     */
    public QueryProcessor(final HadoopConfigBean hcb, final PolicyMaster policy) {

        this.policy = policy;
        final KafkaConfigBean kcb = hcb.getKafkaConfigBean();
        this.violationTopic = kcb.getViolationTopic();

        final Properties props = new Properties();
        props.put("source", HadoopConfigBean.KAFKA_SOURCE.CLUSTER);

        eeoProducer = (EEOProducer) KafkaProducerFactory.INSTANCE.getProducer(KafkaProducerFactory.TYPE_OF_MESSAGE.EEO, kcb, props);

        LOGGER.debug("Query processor initialized!");
    }

    /**
     * Processes the query and publishes violations to the topic
     *
     * @param query Query to be processed
     */
    public void process(final String query) {

        List<HashMap<String, Object>> events = null;
        long resultCount;
        int offset = 0;

        boolean recordsAvailable = true;
        while (recordsAvailable) {

            LOGGER.debug("Querying with Offset:{} Max:{} Q:{} ..", offset, BATCH_SIZE, query);

            try {
                events = ImpalaDbUtil.executeImapalaQueryByEventTime(query, offset, BATCH_SIZE);
            } catch (Exception ex) {
                LOGGER.error("Error getting results from HDFS", ex);
            }

            if (events == null || events.isEmpty()) {
                LOGGER.warn("No response from HDFS!");
                recordsAvailable = false;

            } else {
                resultCount = events.size();
                LOGGER.debug("Total documents # {} Returned # {}", resultCount, events.size());

                // process hdfs details and collect violations data
                publishViolations(events.iterator());

                if (recordsAvailable = resultCount >= BATCH_SIZE) {
                    offset += BATCH_SIZE;
                } else {
                    LOGGER.debug("NO MORE RESULTS FROM HDFS!");
                }
            }
        }
    }

    private static final HashMap<Long, Tuple2<ViolationDisplayConfigBean, List<String>>> vInfoConfig = new HashMap<>();
    
    // DO NOT CHANGE BELOW
    // To do: change name to PublishViolations

    private void publishViolations(final Iterator<HashMap<String, Object>> iterator) {

        LOGGER.debug("Updating violations ..");

        final List<EnrichedEventObject> violationList = new ArrayList<>();

        // eeo object will have complete event details (along-with violations details) 
        EnrichedEventObject eeo;

        ViolationInfo vi;
        Violation v;
        HashMap<Long, Map<String, ViolationDetails>> vdDetails;
        List<Violation> violations;
        final Long policyId = policy.getId();
        final String policyName = policy.getName();

        final String violator = policy.getViolator();
        final long riskthreatid = policy.getRiskthreatid();
        final String threatname = policy.getThreatname();
        final long riskTypeId = policy.getRiskTypeId();
        final Integer categoryid = policy.getCategoryid();
        final String category = policy.getCategory();
        final double riskScore = PolicyConstants.CRITICALITY_MAP.get(policy.getCriticality());

        String violationdisplayconfig = policy.getViolationdisplayconfig();
        if (violationdisplayconfig != null && !violationdisplayconfig.isEmpty()) {
            List<ViolationDisplayConfigBean> displayConfigBeans = JAXBUtilImpl.xmlToPojos(violationdisplayconfig, ViolationDisplayConfigBean.class);
            ViolationDisplayConfigBean displayConfigBean = !displayConfigBeans.isEmpty() ? displayConfigBeans.get(0) : null;
            List<String> parseTemplate = (policy.getVerboseinfotemplate() != null && !policy.getVerboseinfotemplate().isEmpty()) ? CommonUtility.parseTemplate(policy.getVerboseinfotemplate()) : new ArrayList<>();
            vInfoConfig.put(policyId, new Tuple2<>(displayConfigBean, parseTemplate));
        }

        LOGGER.debug("About to form EEOs ..");
        while (iterator.hasNext()) {

            eeo = new EnrichedEventObject();

            // populate eeo object with the help of HDFS details
            EEOUtil.populateEEO(iterator.next(), eeo);

            eeo.setViolations(violations = new ArrayList<>());
            violations.add(v = new Violation(policyId, policyName));

            v.setViolator(violator);
            v.setRiskThreatId(riskthreatid);
            v.setRiskThreatName(threatname);
            v.setRiskTypeId(riskTypeId);
            v.setCategoryId(categoryid);
            v.setCategory(category);

            // Generated Violation Info
            vdDetails = new HashMap<>();
            vi = new ViolationInfo();
            //Deafult Violation info Forms a tree Structure
            String groupingAttribute = null;
            String lvl2Attribute = null;
            List<String> metaDataList = null;
            List<String> level2MetaDataList = null;

            List<String> verboseKeys = null;
            if (vInfoConfig != null && vInfoConfig.containsKey(policyId)) {
                Tuple2<ViolationDisplayConfigBean, List<String>> vInfoDisplayConfig = vInfoConfig.get(policyId);

                if (vInfoConfig.get(policyId)._1() != null) {
                    if (vInfoDisplayConfig._1().getDisplayAttributes() != null && !vInfoDisplayConfig._1().getDisplayAttributes().isEmpty()) {
                        groupingAttribute = vInfoDisplayConfig._1().getDisplayAttributes().get(0);
                    }
                    lvl2Attribute = vInfoDisplayConfig._1().getLevel2Attributes();
                    metaDataList = vInfoDisplayConfig._1().getMetadataAttributes();
                    level2MetaDataList = vInfoDisplayConfig._1().getLevel2MetaDataAttr();
                }
                if (vInfoConfig.get(policyId)._2() != null) {
                    verboseKeys = vInfoDisplayConfig._2();
                }
            }

            final Map<String, Object> params = new HashMap<>();
            params.put(ViolationInfoConstants.FUNCTION_TYPE, ViolationInfoConstants.TREEPOLICYTYPE);
            params.put(ViolationDetailsTree.PARAMS.GROUP_ATTRIBUTE.name(), groupingAttribute);
            params.put(ViolationDetailsTree.PARAMS.LVL2_ATTRIBUTE.name(), lvl2Attribute);
            params.put(ViolationDetailsTree.PARAMS.METADATA_LIST.name(), metaDataList);
            params.put(ViolationDetailsTree.PARAMS.LVL2_METADATA.name(), level2MetaDataList);

            Map<String, ViolationDetails> buildViolationDetailsFromViolation = ViolationDetailsFactory.getViolationDetails(ViolationInfoConstants.TREEPOLICYTYPE, eeo, params);

            if (buildViolationDetailsFromViolation != null) {
                vdDetails.put(DateUtil.getScrubbedEpochTimeForDay(eeo.getTenantTz() != null ? eeo.getTenantTz() : "GMT", v.getGenerationTime()), buildViolationDetailsFromViolation);
            }

            vi.setViolationDetails(vdDetails);

            HashMap<Long, Map<String, VerboseInfoDetails>> verboseDetails = new HashMap<>();
            verboseDetails.put(DateUtil.getScrubbedEpochTimeForDay(eeo.getTenantTz() != null ? eeo.getTenantTz() : "GMT", v.getGenerationTime()), ViolationInfoBuildUtil.buildVerbosKeyValueMap(eeo, verboseKeys));

            vi.setVerbosKeyValueMap(verboseDetails);

            v.setViolationInfo(vi);

            v.setRiskScore(riskScore);

            // eeo object is added to violationList
            violationList.add(eeo);
        }

        LOGGER.debug("Violations found # {}", violationList.size());
        if (!violationList.isEmpty()) {
            eeoProducer.publish(violationList, violationTopic);
            LOGGER.debug("Violations published # {}", violationList.size());
            violationList.clear();
        }
    }

}