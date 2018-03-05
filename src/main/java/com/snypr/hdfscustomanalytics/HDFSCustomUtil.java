package com.snypr.hdfscustomanalytics;

import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.impala.ImpalaDbUtil;
import com.securonix.application.policy.PolicyConstants;
import static com.securonix.application.policy.PolicyConstants.BATCH_SIZE;
import com.securonix.snyper.common.EnrichedEventObject;
import com.securonix.snyper.policy.beans.violations.Violation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This HDFSCustomUtil class executes custom query and detect violations from HDFS.
 * The violations are published to the violation topic for downstream risk scoring.
 * @see <code>publish</code> method in the <code>com.securonix.kafkaclient.producers.EEOProducer</code> module
 * @author ManishKumar
 * @version 1.0
 * @since 2017-03-31
 */
public class HDFSCustomUtil {

    private final static Logger LOGGER = LogManager.getLogger();

    // violationList is used to collect all the violations data.
    private final static List<EnrichedEventObject> violationList = new ArrayList<>();
    
   /**
     * executeCustomPolicy method is used to executes custom query on HDFS.
     * EEO object gets generated from HDFS records.Detected violations get publish into the Violation Topic.
     * @throws java.lang.Exception
     * @author ManishKumar
     * @version 1.0
     * @since 2017-03-31
     * @see <code>publish</code> in the <code>com.securonix.kafkaclient.producers.EEOProducer</code> module
     */

    public static void executeCustomPolicy(PolicyMaster policy) throws Exception {

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

    /*
    This method is used to process violation query.
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

    /*
    This methid is used to process HDFS data and generate/collect violations
     */
    public static void collectViolations(final Iterator<HashMap<String, Object>> iterator) {

        LOGGER.debug("[Updating violations ..");

        // eeo object will have complete event details (along-with violations details) 
        EnrichedEventObject eeo;

        // violations : this will have violations details with-in eeo object 
        List<Violation> violations;
        Violation v;

        final Long policyId = HDFSCustomExecutor.policy.getId();
        final String policyName = HDFSCustomExecutor.policy.getName();

        final String violator = HDFSCustomExecutor.policy.getViolator();
        final long riskthreatid = HDFSCustomExecutor.policy.getRiskthreatid();
        final String threatname = HDFSCustomExecutor.policy.getThreatname();
        final long riskTypeId = HDFSCustomExecutor.policy.getRiskTypeId();
        final Integer categoryid = HDFSCustomExecutor.policy.getCategoryid();
        final String category = HDFSCustomExecutor.policy.getCategory();
        final double riskScore = PolicyConstants.CRITICALITY_MAP.get(HDFSCustomExecutor.policy.getCriticality());

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
