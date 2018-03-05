package com.snypr.hdfscustomanalytics;

import com.securonix.application.common.CommonUtility;
import com.securonix.application.impala.ImpalaDbUtil;
import com.securonix.application.policy.PolicyConstants;
import static com.securonix.application.policy.PolicyConstants.BATCH_SIZE;
import com.securonix.application.profiler.uiUtil.JAXBUtilImpl;
import com.securonix.application.suspect.ViolationInfoBuildUtil;
import com.securonix.snyper.common.EnrichedEventObject;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import scala.Tuple2;

/**
 * This HDFSCustomUtil class executes custom query and detect violations from
 * HDFS. The violations are published to the violation topic for downstream risk
 * scoring.
 *
 * @see <code>publish</code> method in the
 * <code>com.securonix.kafkaclient.producers.EEOProducer</code> module
 * @author ManishKumar
 * @version 1.0
 * @since 2017-03-31
 */
public class HDFSCustomUtil {

    private final static Logger LOGGER = LogManager.getLogger();

    // violationList is used to collect all the violations data.
    private final static List<EnrichedEventObject> violationList = new ArrayList<>();
    private static final HashMap<Long, Tuple2<ViolationDisplayConfigBean, List<String>>> vInfoConfig = new HashMap<>();

    /**
     * executeCustomPolicy method is used to executes custom query on HDFS. EEO
     * object gets generated from HDFS records.Detected violations get publish
     * into the Violation Topic.
     *
     * @throws java.lang.Exception
     * @author ManishKumar
     * @version 1.0
     * @since 2017-03-31
     * @see <code>publish</code> in the
     * <code>com.securonix.kafkaclient.producers.EEOProducer</code> module
     */
    public static void executeCustomPolicy() throws Exception {

        // violationEvents is used to collect all the events, which are detected as violations.
        List<HashMap<String, Object>> violationEvents = null;

        // violationQuery is sample query, which is used to get violation entities.
        final String violationQuery = "select accountname, year, month, dayofmonth, hour, minute from securonixresource162incoming where transactionstring1='LOGON FAILED' group by accountname, year, month, dayofmonth, hour, minute having count(accountname)>5";

        try {
            // Get violations entiteis from HDFS
            violationEvents = ImpalaDbUtil.executeQuery(violationQuery);
        } catch (Exception ex) {
            LOGGER.error("Error getting results from HDFS ", ex);
        }

        if (violationEvents != null && !violationEvents.isEmpty()) {

            for (HashMap<String, Object> violationEvent : violationEvents) {

                String account = (String) violationEvent.get("accountname");
                String year = (String) violationEvent.get("year");
                String month = (String) violationEvent.get("month");
                String day = (String) violationEvent.get("dayofmonth");
                String hour = (String) violationEvent.get("hour");
                String minute = (String) violationEvent.get("minute");

                String violationDetailQuery = "select * from securonixresource162incoming where accountname='" + account + "' and year=" + year + " and month=" + month + " and dayofmonth=" + day + " and hour =" + hour + " and minute=" + minute;

                LOGGER.debug("Query- {}", violationDetailQuery);
                try {
                    processHdfsQuery(violationDetailQuery);
                } catch (Exception ex) {
                    LOGGER.warn("Unable to replace value in {}", violationDetailQuery, ex);
                }

            }

        } else {
            LOGGER.info("No Violation found");
        }

    }

   
    /**
     * processHdfsQuery method is used to executes and fetch records from HDFS.
     *
     * @author ManishKumar
     * @version 1.0
     * @param query parameter is used to fetch records from HDFS.
     * @since 2017-03-31
     */
    
    public static void processHdfsQuery(final String query) {

        List<HashMap<String, Object>> events = null;
        long resultCount;
        int offset = 0;

        boolean recordsAvailable = true;
        while (recordsAvailable) {

            LOGGER.debug("Querying with Offset:{} Max:{} Q:{} ..", offset, BATCH_SIZE, query);

            try {

                // Get all violations events
                events = ImpalaDbUtil.executeImapalaQuery(query, offset, BATCH_SIZE);
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
                collectViolations(events.iterator());

                if (recordsAvailable = resultCount >= BATCH_SIZE) {
                    offset += BATCH_SIZE;
                } else {
                    LOGGER.debug("NO MORE RESULTS FROM HDFS!");
                }
            }
        }

    }
    
    
    /**
     * collectViolations method is used to process HDFS data and generate EEO object List.
     *
     * @author ManishKumar
     * @version 1.0
     * @param iterator parameter is used to  have reference of each HDFS record.  
     * @since 2017-03-31
     */

    /*
    This methid is used to process HDFS data and generate/collect violations
     */
    public static void collectViolations(final Iterator<HashMap<String, Object>> iterator) {

        LOGGER.debug("[Updating violations ..");

        // eeo object will have complete event details (along-with violations details) 
        EnrichedEventObject eeo;

        ViolationInfo vi;
        Violation v;
        HashMap<Long, Map<String, ViolationDetails>> vdDetails;
        List<Violation> violations;
        final Long policyId = HDFSCustomExecutor.policy.getId();
        final String policyName = HDFSCustomExecutor.policy.getName();

        final String violator = HDFSCustomExecutor.policy.getViolator();
        final long riskthreatid = HDFSCustomExecutor.policy.getRiskthreatid();
        final String threatname = HDFSCustomExecutor.policy.getThreatname();
        final long riskTypeId = HDFSCustomExecutor.policy.getRiskTypeId();
        final Integer categoryid = HDFSCustomExecutor.policy.getCategoryid();
        final String category = HDFSCustomExecutor.policy.getCategory();
        final double riskScore = PolicyConstants.CRITICALITY_MAP.get(HDFSCustomExecutor.policy.getCriticality());
        String violationdisplayconfig = HDFSCustomExecutor.policy.getViolationdisplayconfig();
        if (violationdisplayconfig != null && !violationdisplayconfig.isEmpty()) {
            List<ViolationDisplayConfigBean> displayConfigBeans = JAXBUtilImpl.xmlToPojos(violationdisplayconfig, ViolationDisplayConfigBean.class);
            ViolationDisplayConfigBean displayConfigBean = !displayConfigBeans.isEmpty() ? displayConfigBeans.get(0) : null;
            List<String> parseTemplate = (HDFSCustomExecutor.policy.getVerboseinfotemplate() != null && !HDFSCustomExecutor.policy.getVerboseinfotemplate().isEmpty()) ? CommonUtility.parseTemplate(HDFSCustomExecutor.policy.getVerboseinfotemplate()) : new ArrayList<>();
            vInfoConfig.put(policyId, new Tuple2<>(displayConfigBean, parseTemplate));
        }

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

        if (!violationList.isEmpty()) {
            HDFSCustomExecutor.eeoProducer.publish(violationList, HDFSCustomExecutor.violationTopic);
            LOGGER.debug("Violations published # {}", violationList.size());
            violationList.clear();
        }
    }

}
