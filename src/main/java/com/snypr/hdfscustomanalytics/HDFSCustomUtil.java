package com.snypr.hdfscustomanalytics;

import static com.securonix.application.hadoop.uiUtil.websocket.MappedAttributeList.*;
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
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class includes all required utility methods,those are used to perform custom analytics and processing of
 * violations data.
 *
 * @author manishkumar
 */
public class HDFSCustomUtil {

    private final static Logger LOGGER = LogManager.getLogger();

    // violationList is used to collect all the violations data.
    private final static List<EnrichedEventObject> violationList = new ArrayList<>();

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
            populateEEO(iterator.next(), eeo);

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

    /*
    This method is used to create eeo object by using HDFS details
     */
    private static void populateEEO(final Map<String, Object> map, final EnrichedEventObject eeo) {

        Object o;

        if ((o = map.get(EVENTID)) != null) {
            eeo.setEventid((String) o);
        }
        if ((o = map.get(EVENTTIME)) != null) {
            if (o instanceof Long) {
                eeo.setEventtime((Long) o);
            } else {
                try {
                    eeo.setEventtime(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing event time", ex);
                }
            }
        }
        if ((o = map.get(ACCOUNTNAME)) != null) {
            eeo.setAccountname((String) o);
        }

        if ((o = map.get(YEAR)) != null) {
            if (o instanceof Integer) {
                eeo.setYear((Integer) o);
            } else {
                try {
                    eeo.setYear(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing year", ex);
                }
            }
        }
        if ((o = map.get(WEEK)) != null) {
            if (o instanceof Integer) {
                eeo.setWeek((Integer) o);
            } else {
                try {
                    eeo.setWeek(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing week", ex);
                }
            }
        }
        if ((o = map.get(MONTH)) != null) {
            if (o instanceof Integer) {
                eeo.setMonth((Integer) o);
            } else {
                try {
                    eeo.setMonth(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing month", ex);
                }
            }
        }
        if ((o = map.get(DAYOFYEAR)) != null) {
            if (o instanceof Integer) {
                eeo.setDayofyear((Integer) o);
            } else {
                try {
                    eeo.setDayofyear(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing day of year", ex);
                }
            }
        }
        if ((o = map.get(DAYOFWEEK)) != null) {
            if (o instanceof Integer) {
                eeo.setDayofweek((Integer) o);
            } else {
                try {
                    eeo.setDayofweek(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing day of week", ex);
                }
            }
        }
        if ((o = map.get(DAYOFMONTH)) != null) {
            if (o instanceof Integer) {
                eeo.setDayofmonth((Integer) o);
            } else {
                try {
                    eeo.setDayofmonth(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing day of month", ex);
                }
            }
        }
        if ((o = map.get(HOUR)) != null) {
            if (o instanceof Integer) {
                eeo.setHour((Integer) o);
            } else {
                try {
                    eeo.setHour(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing hour", ex);
                }
            }
        }
        if ((o = map.get(MINUTE)) != null) {
            if (o instanceof Integer) {
                eeo.setMinute((Integer) o);
            } else {
                try {
                    eeo.setMinute(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing minute", ex);
                }
            }
        }

        if ((o = map.get(RAWEVENT)) != null) {
            eeo.setRawevent((String) o);
        }

        if ((o = map.get(U_ID)) != null) {
            if (o instanceof Long) {
                eeo.setU_id((Long) o);
            } else {
                try {
                    eeo.setU_id(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing UId", ex);
                }
            }
        }

        if ((o = map.get(U_EMPLOYEEID)) != null) {
            eeo.setU_employeeid((String) o);
        }

        if ((o = map.get(U_FIRSTNAME)) != null) {
            eeo.setU_firstname((String) o);
        }
        if ((o = map.get(U_MIDDLENAME)) != null) {
            eeo.setU_middlename((String) o);
        }
        if ((o = map.get(U_LASTNAME)) != null) {
            eeo.setU_lastname((String) o);
        }

        if ((o = map.get(U_DEPARTMENT)) != null) {
            eeo.setU_department((String) o);
        }
        if ((o = map.get(U_DIVISION)) != null) {
            eeo.setU_division((String) o);
        }
        if ((o = map.get(U_LOCATION)) != null) {
            eeo.setU_location((String) o);
        }
        if ((o = map.get(U_MANAGEREMPLOYEEID)) != null) {
            eeo.setU_manageremployeeid((String) o);
        }
        if ((o = map.get(U_WORKEMAIL)) != null) {
            eeo.setU_workemail((String) o);
        }
        if ((o = map.get(U_WORKPHONE)) != null) {
            eeo.setU_workphone((String) o);
        }
        if ((o = map.get(U_TITLE)) != null) {
            eeo.setU_title((String) o);
        }
        if ((o = map.get(U_EMPLOYEETYPE)) != null) {
            eeo.setU_employeetype((String) o);
        }
        if ((o = map.get(U_STATUS)) != null) {
            if (o instanceof Integer) {
                eeo.setU_status((Integer) o);
            } else {
                try {
                    eeo.setU_status(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing user status", ex);
                }
            }
        }
        if ((o = map.get(U_UNIQUECODE)) != null) {
            eeo.setU_uniquecode((String) o);
        }
        if ((o = map.get(U_RISKSCORE)) != null) {
            if (o instanceof Double) {
                eeo.setU_riskscore((Double) o);
            } else {
                try {
                    eeo.setU_riskscore(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing user risk score", ex);
                }
            }
        }

        if ((o = map.get(U_CUSTOMFIELD1)) != null) {
            eeo.setU_customfield1((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD2)) != null) {
            eeo.setU_customfield2((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD3)) != null) {
            eeo.setU_customfield3((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD4)) != null) {
            eeo.setU_customfield4((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD5)) != null) {
            eeo.setU_customfield5((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD6)) != null) {
            eeo.setU_customfield6((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD7)) != null) {
            eeo.setU_customfield7((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD8)) != null) {
            eeo.setU_customfield8((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD9)) != null) {
            eeo.setU_customfield9((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD10)) != null) {
            eeo.setU_customfield10((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD11)) != null) {
            eeo.setU_customfield11((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD12)) != null) {
            eeo.setU_customfield12((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD13)) != null) {
            eeo.setU_customfield13((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD14)) != null) {
            eeo.setU_customfield14((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD15)) != null) {
            eeo.setU_customfield15((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD16)) != null) {
            eeo.setU_customfield16((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD17)) != null) {
            eeo.setU_customfield17((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD18)) != null) {
            eeo.setU_customfield18((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD19)) != null) {
            eeo.setU_customfield19((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD20)) != null) {
            eeo.setU_customfield20((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD21)) != null) {
            if (o instanceof Double) {
                eeo.setU_customfield21((Double) o);
            } else {
                try {
                    eeo.setU_customfield21(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing custom field 21", ex);
                }
            }
        }
        if ((o = map.get(U_CUSTOMFIELD22)) != null) {
            if (o instanceof Double) {
                eeo.setU_customfield22((Double) o);
            } else {
                try {
                    eeo.setU_customfield22(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing custom field 22", ex);
                }
            }
        }
        if ((o = map.get(U_CUSTOMFIELD23)) != null) {
            if (o instanceof Double) {
                eeo.setU_customfield23((Double) o);
            } else {
                try {
                    eeo.setU_customfield23(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing custom field 23", ex);
                }
            }
        }
        if ((o = map.get(U_CUSTOMFIELD24)) != null) {
            eeo.setU_customfield24((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD25)) != null) {
            eeo.setU_customfield25((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD26)) != null) {
            eeo.setU_customfield26((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD27)) != null) {
            eeo.setU_customfield27((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD28)) != null) {
            eeo.setU_customfield28((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD29)) != null) {
            eeo.setU_customfield29((String) o);
        }
        if ((o = map.get(U_CUSTOMFIELD30)) != null) {
            eeo.setU_customfield30((String) o);
        }

        if ((o = map.get(U_PROMOTED)) != null) {
            eeo.setU_promoted((String) o);
        }
        if ((o = map.get(U_CREATEDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_createdate((Long) o);
            } else {
                try {
                    eeo.setU_createdate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing create date", ex);
                }
            }
        }

        if ((o = map.get(U_USERGROUP)) != null) {
            eeo.setU_usergroup((String) o);
        }
        if ((o = map.get(U_STREET)) != null) {
            eeo.setU_street((String) o);
        }
        if ((o = map.get(U_CITY)) != null) {
            eeo.setU_city((String) o);
        }
        if ((o = map.get(U_PROVINCE)) != null) {
            eeo.setU_province((String) o);
        }
        if ((o = map.get(U_ZIPCODE)) != null) {
            eeo.setU_zipcode((String) o);
        }
        if ((o = map.get(U_USERSTATE)) != null) {
            eeo.setU_userstate((String) o);
        }
        if ((o = map.get(U_REGION)) != null) {
            eeo.setU_region((String) o);
        }
        if ((o = map.get(U_COUNTRY)) != null) {
            eeo.setU_country((String) o);
        }

        if ((o = map.get(U_APPROVEREMPLOYEEID)) != null) {
            eeo.setU_approveremployeeid((String) o);
        }
        if ((o = map.get(U_DELEGATEEMPLOYEEID)) != null) {
            eeo.setU_delegateemployeeid((String) o);
        }
        if ((o = map.get(U_TECHNICALAPPROVERID)) != null) {
            eeo.setU_technicalapproverid((String) o);
        }
        if ((o = map.get(U_EXTENSION)) != null) {
            eeo.setU_extension((String) o);
        }
        if ((o = map.get(U_FAX)) != null) {
            eeo.setU_fax((String) o);
        }
        if ((o = map.get(U_MOBILE)) != null) {
            eeo.setU_mobile((String) o);
        }
        if ((o = map.get(U_PAGER)) != null) {
            eeo.setU_pager((String) o);
        }
        if ((o = map.get(U_JOBCODE)) != null) {
            eeo.setU_jobcode((String) o);
        }
        if ((o = map.get(U_COMMENTS)) != null) {
            eeo.setU_comments((String) o);
        }
        if ((o = map.get(U_CREATEDBY)) != null) {
            eeo.setU_createdby((String) o);
        }

        if ((o = map.get(U_COSTCENTERNAME)) != null) {
            eeo.setU_costcentername((String) o);
        }
        if ((o = map.get(U_COSTCENTERCODE)) != null) {
            eeo.setU_costcentercode((String) o);
        }
        if ((o = map.get(U_ENABLEDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_enabledate((Long) o);
            } else {
                try {
                    eeo.setU_enabledate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing enable date", ex);
                }
            }
        }
        if ((o = map.get(U_DISABLEDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_disabledate((Long) o);
            } else {
                try {
                    eeo.setU_disabledate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing disable date", ex);
                }
            }
        }
        if ((o = map.get(U_DELETEDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_deletedate((Long) o);
            } else {
                try {
                    eeo.setU_deletedate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing delete date", ex);
                }
            }
        }
        if ((o = map.get(U_UPDATEDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_updatedate((Long) o);
            } else {
                try {
                    eeo.setU_updatedate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing update date", ex);
                }
            }
        }
        if ((o = map.get(U_SUNRISEDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_sunrisedate((Long) o);
            } else {
                try {
                    eeo.setU_sunrisedate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing sunrise date", ex);
                }
            }
        }
        if ((o = map.get(U_SUNSETDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_sunsetdate((Long) o);
            } else {
                try {
                    eeo.setU_sunsetdate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing sunset date", ex);
                }
            }
        }

        if ((o = map.get(U_CRITICALITY)) != null) {
            eeo.setU_criticality((String) o);
        }
        if ((o = map.get(U_DOMINTLIN)) != null) {
            eeo.setU_domintlin((String) o);
        }

        if ((o = map.get(U_NAMEPREFIX)) != null) {
            eeo.setU_nameprefix((String) o);
        }
        if ((o = map.get(U_NAMESUFFIX)) != null) {
            eeo.setU_namesuffix((String) o);
        }
        if ((o = map.get(U_PREFERREDNAME)) != null) {
            eeo.setU_preferredname((String) o);
        }
        if ((o = map.get(U_SECONDARYPHONE)) != null) {
            eeo.setU_secondaryphone((String) o);
        }
        if ((o = map.get(U_STATUSDESCRIPTION)) != null) {
            eeo.setU_statusdescription((String) o);
        }

        if ((o = map.get(U_VACATIONSTART)) != null) {
            if (o instanceof Long) {
                eeo.setU_vacationstart((Long) o);
            } else {
                try {
                    eeo.setU_vacationstart(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing vacation start", ex);
                }
            }
        }
        if ((o = map.get(U_VACATIONEND)) != null) {
            if (o instanceof Long) {
                eeo.setU_vacationend((Long) o);
            } else {
                try {
                    eeo.setU_vacationend(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing vacation end", ex);
                }
            }
        }

        if ((o = map.get(U_NETWORKID)) != null) {
            eeo.setU_networkid((String) o);
        }
        if ((o = map.get(U_WORKPAGER)) != null) {
            eeo.setU_workpager((String) o);
        }
        if ((o = map.get(U_WORKEXTENSIONNUMBER)) != null) {
            eeo.setU_workextensionnumber((String) o);
        }
        if ((o = map.get(U_WORKFAX)) != null) {
            eeo.setU_workfax((String) o);
        }
        if ((o = map.get(U_EMPLOYEESTATUSCODE)) != null) {
            eeo.setU_employeestatuscode((String) o);
        }
        if ((o = map.get(U_LOCATIONCODE)) != null) {
            eeo.setU_locationcode((String) o);
        }
        if ((o = map.get(U_LOCATIONNAME)) != null) {
            eeo.setU_locationname((String) o);
        }
        if ((o = map.get(U_MAILCODE)) != null) {
            eeo.setU_mailcode((String) o);
        }

        if ((o = map.get(U_HIREDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_hiredate((Long) o);
            } else {
                try {
                    eeo.setU_hiredate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing hire date", ex);
                }
            }
        }
        if ((o = map.get(U_REHIREDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_rehiredate((Long) o);
            } else {
                try {
                    eeo.setU_rehiredate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing rehire date", ex);
                }
            }
        }
        if ((o = map.get(U_RECENTHIREDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_recenthiredate((Long) o);
            } else {
                try {
                    eeo.setU_recenthiredate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing recent hire date", ex);
                }
            }
        }
        if ((o = map.get(U_TERMINATIONDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_terminationdate((Long) o);
            } else {
                try {
                    eeo.setU_terminationdate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing termination date", ex);
                }
            }
        }
        if ((o = map.get(U_LASTDAYWORKED)) != null) {
            if (o instanceof Long) {
                eeo.setU_lastdayworked((Long) o);
            } else {
                try {
                    eeo.setU_lastdayworked(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing last day worked", ex);
                }
            }
        }
        if ((o = map.get(U_CONTRACTSTARTDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_contractstartdate((Long) o);
            } else {
                try {
                    eeo.setU_contractstartdate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing contract start date", ex);
                }
            }
        }
        if ((o = map.get(U_CONTRACTENDDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_contractenddate((Long) o);
            } else {
                try {
                    eeo.setU_contractenddate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing contract end date", ex);
                }
            }
        }

        if ((o = map.get(U_EMPLOYEETYPEDESCRIPTION)) != null) {
            eeo.setU_employeetypedescription((String) o);
        }
        if ((o = map.get(U_REGTEMPIN)) != null) {
            eeo.setU_regtempin((String) o);
        }
        if ((o = map.get(U_FULLTIMEPARTTIMEIN)) != null) {
            eeo.setU_fulltimeparttimein((String) o);
        }
        if ((o = map.get(U_MANAGERFIRSTNAME)) != null) {
            eeo.setU_managerfirstname((String) o);
        }
        if ((o = map.get(U_MANAGERLASTNAME)) != null) {
            eeo.setU_managerlastname((String) o);
        }
        if ((o = map.get(U_MANAGERMIDDLENAME)) != null) {
            eeo.setU_managermiddlename((String) o);
        }
        if ((o = map.get(U_ORGUNITNUMBER)) != null) {
            eeo.setU_orgunitnumber((String) o);
        }
        if ((o = map.get(U_COMPANYCODE)) != null) {
            eeo.setU_companycode((String) o);
        }
        if ((o = map.get(U_COMPANYNUMBER)) != null) {
            eeo.setU_companynumber((String) o);
        }
        if ((o = map.get(U_HIERARCHY)) != null) {
            eeo.setU_hierarchy((String) o);
        }
        if ((o = map.get(U_LASTPERFORMANCEREVIEWDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_lastperformancereviewdate((Long) o);
            } else {
                try {
                    eeo.setU_lastperformancereviewdate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing last performance review date", ex);
                }
            }
        }
        if ((o = map.get(U_LASTPERFORMANCEREVIEWRESULT)) != null) {
            eeo.setU_lastperformancereviewresult((String) o);
        }
        if ((o = map.get(U_STANDARDHOURS)) != null) {
            eeo.setU_standardhours((String) o);
        }
        if ((o = map.get(U_SHIFTCODE)) != null) {
            eeo.setU_shiftcode((String) o);
        }
        if ((o = map.get(U_SHIFTNAME)) != null) {
            eeo.setU_shiftname((String) o);
        }
        if ((o = map.get(U_LANID)) != null) {
            eeo.setU_lanid((String) o);
        }
        if ((o = map.get(U_USERID)) != null) {
            eeo.setU_userid((String) o);
        }
        if ((o = map.get(U_TRANSFERREDDATE)) != null) {
            if (o instanceof Long) {
                eeo.setU_transferreddate((Long) o);
            } else {
                try {
                    eeo.setU_transferreddate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing transferred date", ex);
                }
            }
        }
        if ((o = map.get(U_DATASOURCEID)) != null) {
            if (o instanceof Long) {
                eeo.setU_datasourceid((Long) o);
            } else {
                try {
                    eeo.setU_datasourceid(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing data source Id", ex);
                }
            }
        }
        if ((o = map.get(U_TIMEZONEOFFSET)) != null) {
            eeo.setU_timezoneoffset((String) o);
        }
        if ((o = map.get(U_ENCRYPTED)) != null) {
            if (o instanceof Boolean) {
                eeo.setU_encrypted((Boolean) o);
            } else {
                try {
                    eeo.setU_encrypted(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing encrypted flag", ex);
                }
            }
        }
        if ((o = map.get(U_ENCRYPTEDFIELDS)) != null) {
            eeo.setU_encryptedfields((String) o);
        }
        if ((o = map.get(U_MASKEDFIELDS)) != null) {
            eeo.setU_maskedfields((String) o);
        }
        if ((o = map.get(U_MASKED)) != null) {
            if (o instanceof Boolean) {
                eeo.setU_masked((Boolean) o);
            } else {
                try {
                    eeo.setU_masked(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing masked flag", ex);
                }
            }
        }
        if ((o = map.get(U_LASTSYNCTIME)) != null) {
            if (o instanceof Long) {
                eeo.setU_lastsynctime((Long) o);
            } else {
                try {
                    eeo.setU_lastsynctime(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing last sync time", ex);
                }
            }
        }
        if ((o = map.get(U_MERGEUNIQUECODE)) != null) {
            eeo.setU_mergeuniquecode((String) o);
        }
        if ((o = map.get(U_SKIPENCRYPTION)) != null) {
            if (o instanceof Boolean) {
                eeo.setU_skipencryption((Boolean) o);
            } else {
                try {
                    eeo.setU_skipencryption(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing skip encryption flag", ex);
                }
            }
        }

        if ((o = map.get(RG_ID)) != null) {
            if (o instanceof Long) {
                eeo.setRg_id((Long) o);
            } else {
                try {
                    eeo.setRg_id(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg id", ex);
                }
            }
        }
        if ((o = map.get(RG_NAME)) != null) {
            eeo.setRg_name((String) o);
        }
        if ((o = map.get(RG_TYPE)) != null) {
            eeo.setRg_type((String) o);
        }
        if ((o = map.get(RG_VENDOR)) != null) {
            eeo.setRg_vendor((String) o);
        }
        if ((o = map.get(RG_FUNCTIONALITY)) != null) {
            eeo.setRg_functionality((String) o);
        }
        if ((o = map.get(RG_OWNERID)) != null) {
            if (o instanceof Long) {
                eeo.setRg_ownerid((Long) o);
            } else {
                try {
                    eeo.setRg_ownerid(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg owner id", ex);
                }
            }
        }
        if ((o = map.get(RG_RISKSCORE)) != null) {
            eeo.setRg_riskscore((Double) o);
        }
        if ((o = map.get(RG_CRITICALITY)) != null) {
            eeo.setRg_criticality((String) o);
        }
        if ((o = map.get(RG_DEVICEID)) != null) {
            eeo.setRg_deviceid((String) o);
        }
        if ((o = map.get(RG_TIMEZONEOFFSET)) != null) {
            eeo.setRg_timezoneoffset((String) o);
        }
        if ((o = map.get(RG_AGGREGATELEVEL)) != null) {
            eeo.setRg_aggregatelevel((String) o);
        }
        if ((o = map.get(RG_RESOURCETYPEID)) != null) {
            if (o instanceof Long) {
                eeo.setRg_resourcetypeid((Long) o);
            } else {
                try {
                    eeo.setRg_resourcetypeid(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg resource type id", ex);
                }
            }
        }
        if ((o = map.get(RG_CLUSTERID)) != null) {
            if (o instanceof Long) {
                eeo.setRg_clusterid((Long) o);
            } else {
                try {
                    eeo.setRg_clusterid(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg cluster id", ex);
                }
            }
        }
        if ((o = map.get(RG_IPADDRESS)) != null) {
            eeo.setRg_ipaddress((String) o);
        }
        if ((o = map.get(RG_CATEGORY)) != null) {
            eeo.setRg_category((String) o);
        }
        if ((o = map.get(RG_AMOUNTROUNDUPVALUE)) != null) {
            if (o instanceof Integer) {
                eeo.setRg_amountroundupvalue((Integer) o);
            } else {
                try {
                    eeo.setRg_amountroundupvalue(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg amount round up value", ex);
                }
            }
        }
        if ((o = map.get(RG_SYSLOGENABLED)) != null) {
            if (o instanceof Boolean) {
                eeo.setRg_syslogenabled((Boolean) o);
            } else {
                try {
                    eeo.setRg_syslogenabled(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing syslog enabled flag", ex);
                }
            }
        }
        if ((o = map.get(RG_SYSLOGPORT)) != null) {
            if (o instanceof Integer) {
                eeo.setRg_syslogport((Integer) o);
            } else {
                try {
                    eeo.setRg_syslogport(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg syslog port", ex);
                }
            }
        }
        if ((o = map.get(RG_CUSTOMERID)) != null) {
            if (o instanceof Long) {
                eeo.setRg_customerid((Long) o);
            } else {
                try {
                    eeo.setRg_customerid(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg customer id", ex);
                }
            }
        }
        if ((o = map.get(RG_PARENTSTATUS)) != null) {
            if (o instanceof Integer) {
                eeo.setRg_parentstatus((Integer) o);
            } else {
                try {
                    eeo.setRg_parentstatus(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg parent status", ex);
                }
            }
        }
        if ((o = map.get(RG_PARENTID)) != null) {
            if (o instanceof Long) {
                eeo.setRg_parentid((Long) o);
            } else {
                try {
                    eeo.setRg_parentid(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing Rg parent id", ex);
                }
            }
        }
        if ((o = map.get(RG_RETAINEDACCESSENTITLEMENTS)) != null) {
            if (o instanceof Boolean) {
                eeo.setRg_retainedaccessentitlements((Boolean) o);
            } else {
                try {
                    eeo.setRg_retainedaccessentitlements(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing retained access entitlements flag", ex);
                }
            }
        }

        if ((o = map.get(RESOURCENAME)) != null) {
            eeo.setResourcename((String) o);
        }
        if ((o = map.get(RESOURCETYPE)) != null) {
            eeo.setResourcetype((String) o);
        }
        if ((o = map.get(IPADDRESS)) != null) {
            eeo.setIpaddress((String) o);
        }
        if ((o = map.get(OTHERS)) != null) {
            eeo.setOthers((String) o);
        }
        if ((o = map.get(EVENTCOUNT)) != null) {
            eeo.setEventcount((String) o);
        }
        if ((o = map.get(SIEMID)) != null) {
            eeo.setSiemid((String) o);
        }
        if ((o = map.get(FLOWSIEMID)) != null) {
            eeo.setFlowsiemid((String) o);
        }
        if ((o = map.get(ALERTID)) != null) {
            eeo.setAlertid((String) o);
        }

        if ((o = map.get(APPLICATIONPROTOCOL)) != null) {
            eeo.setApplicationprotocol((String) o);
        }
        if ((o = map.get(DESTINATIONHOSTNAME)) != null) {
            eeo.setDestinationhostname((String) o);
        }
        if ((o = map.get(DESTINATIONPROCESSID)) != null) {
            if (o instanceof Integer) {
                eeo.setDestinationprocessid((Integer) o);
            } else {
                try {
                    eeo.setDestinationprocessid(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing destination process id", ex);
                }
            }
        }
        if ((o = map.get(DESTINATIONMACADDRESS)) != null) {
            eeo.setDestinationmacaddress((String) o);
        }
        if ((o = map.get(DESTINATIONNTDOMAIN)) != null) {
            eeo.setDestinationntdomain((String) o);
        }
        if ((o = map.get(DESTINATIONUSERPRIVILEGES)) != null) {
            eeo.setDestinationuserprivileges((String) o);
        }
        if ((o = map.get(DESTINATIONPROCESSNAME)) != null) {
            eeo.setDestinationprocessname((String) o);
        }
        if ((o = map.get(DESTINATIONPORT)) != null) {
            if (o instanceof Integer) {
                eeo.setDestinationport((Integer) o);
            } else {
                try {
                    eeo.setDestinationport(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing destination port", ex);
                }
            }
        }
        if ((o = map.get(DESTINATIONADDRESS)) != null) {
            eeo.setDestinationaddress((String) o);
        }
        if ((o = map.get(DESTINATIONUSERID)) != null) {
            eeo.setDestinationuserid((String) o);
        }
        if ((o = map.get(DESTINATIONUSERNAME)) != null) {
            eeo.setDestinationusername((String) o);
        }
        if ((o = map.get(DESTINATIONDNSDOMAIN)) != null) {
            eeo.setDestinationdnsdomain((String) o);
        }
        if ((o = map.get(SOURCEHOSTNAME)) != null) {
            eeo.setSourcehostname((String) o);
        }
        if ((o = map.get(SOURCEMACADDRESS)) != null) {
            eeo.setSourcemacaddress((String) o);
        }
        if ((o = map.get(SOURCENTDOMAIN)) != null) {
            eeo.setSourcentdomain((String) o);
        }
        if ((o = map.get(SOURCEPROCESSID)) != null) {
            if (o instanceof Integer) {
                eeo.setSourceprocessid((Integer) o);
            } else {
                try {
                    eeo.setSourceprocessid(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing source process id", ex);
                }
            }
        }
        if ((o = map.get(SOURCEPROCESSNAME)) != null) {
            eeo.setSourceprocessname((String) o);
        }
        if ((o = map.get(SOURCEPORT)) != null) {
            if (o instanceof Integer) {
                eeo.setSourceport((Integer) o);
            } else {
                try {
                    eeo.setSourceport(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing source port", ex);
                }
            }
        }
        if ((o = map.get(SOURCEUSERPRIVILEGES)) != null) {
            eeo.setSourceuserprivileges((String) o);
        }
        if ((o = map.get(SOURCEADDRESS)) != null) {
            eeo.setSourceaddress((String) o);
        }
        if ((o = map.get(DEVICEINBOUNDINTERFACE)) != null) {
            eeo.setDeviceinboundinterface((String) o);
        }
        if ((o = map.get(DEVICEOUTBOUNDINTERFACE)) != null) {
            eeo.setDeviceoutboundinterface((String) o);
        }
        if ((o = map.get(DEVICEPROCESSNAME)) != null) {
            eeo.setDeviceprocessname((String) o);
        }
        if ((o = map.get(DEVICESEVERITY)) != null) {
            eeo.setDeviceseverity((String) o);
        }
        if ((o = map.get(DEVICEACTION)) != null) {
            eeo.setDeviceaction((String) o);
        }
        if ((o = map.get(DEVICEEVENTCATEGORY)) != null) {
            eeo.setDeviceeventcategory((String) o);
        }
        if ((o = map.get(DEVICEADDRESS)) != null) {
            eeo.setDeviceaddress((String) o);
        }
        if ((o = map.get(DEVICEHOSTNAME)) != null) {
            eeo.setDevicehostname((String) o);
        }
        if ((o = map.get(DEVICEPROCESSID)) != null) {
            if (o instanceof Integer) {
                eeo.setDeviceprocessid((Integer) o);
            } else {
                try {
                    eeo.setDeviceprocessid(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing device process id", ex);
                }
            }
        }

        if ((o = map.get(FILENAME)) != null) {
            eeo.setFilename((String) o);
        }
        if ((o = map.get(FILESIZE)) != null) {
            if (o instanceof Integer) {
                eeo.setFilesize((Integer) o);
            } else {
                try {
                    eeo.setFilesize(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing file size", ex);
                }
            }
        }
        if ((o = map.get(BYTESIN)) != null) {
            if (o instanceof Integer) {
                eeo.setBytesin((Integer) o);
            } else {
                try {
                    eeo.setBytesin(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing bytes in", ex);
                }
            }
        }
        if ((o = map.get(BYTESOUT)) != null) {
            if (o instanceof Integer) {
                eeo.setBytesout((Integer) o);
            } else {
                try {
                    eeo.setBytesout(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing bytes out", ex);
                }
            }
        }
        if ((o = map.get(FILECREATETIME)) != null) {
            if (o instanceof Long) {
                eeo.setFilecreatetime((Long) o);
            } else {
                try {
                    eeo.setFilecreatetime(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing file create time", ex);
                }
            }
        }
        if ((o = map.get(FILEMODIFICATIONTIME)) != null) {
            if (o instanceof Long) {
                eeo.setFilemodificationtime((Long) o);
            } else {
                try {
                    eeo.setFilemodificationtime(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing file modification time", ex);
                }
            }
        }
        if ((o = map.get(FILEPATH)) != null) {
            eeo.setFilepath((String) o);
        }
        if ((o = map.get(FILETYPE)) != null) {
            eeo.setFiletype((String) o);
        }
        if ((o = map.get(OLDFILENAME)) != null) {
            eeo.setOldfilename((String) o);
        }
        if ((o = map.get(OLDFILEPATH)) != null) {
            eeo.setOldfilepath((String) o);
        }
        if ((o = map.get(OLDFILESIZE)) != null) {
            if (o instanceof Integer) {
                eeo.setOldfilesize((Integer) o);
            } else {
                try {
                    eeo.setOldfilesize(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing old file size", ex);
                }
            }
        }
        if ((o = map.get(OLDFILETYPE)) != null) {
            eeo.setOldfiletype((String) o);
        }

        if ((o = map.get(MESSAGE)) != null) {
            eeo.setMessage((String) o);
        }
        if ((o = map.get(EVENTOUTCOME)) != null) {
            eeo.setEventoutcome((String) o);
        }
        if ((o = map.get(TRANSPORTPROTOCOL)) != null) {
            eeo.setTransportprotocol((String) o);
        }
        if ((o = map.get(REQUESTURL)) != null) {
            eeo.setRequesturl((String) o);
        }
        if ((o = map.get(ZONE)) != null) {
            eeo.setZone((String) o);
        }
        if ((o = map.get(CLASSIFICATION)) != null) {
            eeo.setClassification((String) o);
        }
        if ((o = map.get(REQUESTCLIENTAPPLICATION)) != null) {
            eeo.setRequestclientapplication((String) o);
        }
        if ((o = map.get(REQUESTCONTEXT)) != null) {
            eeo.setRequestcontext((String) o);
        }
        if ((o = map.get(REQUESTMETHOD)) != null) {
            eeo.setRequestmethod((String) o);
        }

        if ((o = map.get(TRANSLATEDIPADDRESS)) != null) {
            eeo.setTranslatedipaddress((String) o);
        }
        if ((o = map.get(TRANSLATEDPORT)) != null) {
            if (o instanceof Integer) {
                eeo.setTranslatedport((Integer) o);
            } else {
                try {
                    eeo.setTranslatedport(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing translated port", ex);
                }
            }
        }
        if ((o = map.get(SESSIONID)) != null) {
            eeo.setSessionid((String) o);
        }
        if ((o = map.get(TRANSACTIONSTRING1)) != null) {
            eeo.setTransactionstring1((String) o);
        }
        if ((o = map.get(TRANSACTIONSTRING2)) != null) {
            eeo.setTransactionstring2((String) o);
        }
        if ((o = map.get(TRANSACTIONSTRING3)) != null) {
            eeo.setTransactionstring3((String) o);
        }
        if ((o = map.get(TRANSACTIONSTRING4)) != null) {
            eeo.setTransactionstring4((String) o);
        }
        if ((o = map.get(TRANSACTIONSTRING5)) != null) {
            eeo.setTransactionstring5((String) o);
        }
        if ((o = map.get(TRANSACTIONSTRING6)) != null) {
            eeo.setTransactionstring6((String) o);
        }
        if ((o = map.get(CATEGORYOBJECT)) != null) {
            eeo.setCategoryobject((String) o);
        }
        if ((o = map.get(CATEGORYBEHAVIOR)) != null) {
            eeo.setCategorybehavior((String) o);
        }
        if ((o = map.get(CATEGORIZEDTIME)) != null) {
            eeo.setCategorizedtime((String) o);
        }
        if ((o = map.get(TRANSACTIONNUMBER1)) != null) {
            if (o instanceof Double) {
                eeo.setTransactionnumber1((Double) o);
            } else {
                try {
                    eeo.setTransactionnumber1(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing transaction number 1", ex);
                }
            }
        }
        if ((o = map.get(TRANSACTIONNUMBER2)) != null) {
            if (o instanceof Double) {
                eeo.setTransactionnumber2((Double) o);
            } else {
                try {
                    eeo.setTransactionnumber2(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing transaction number 2", ex);
                }
            }
        }
        if ((o = map.get(TRANSACTIONNUMBER3)) != null) {
            if (o instanceof Double) {
                eeo.setTransactionnumber3((Double) o);
            } else {
                try {
                    eeo.setTransactionnumber3(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing transaction number 3", ex);
                }
            }
        }
        if ((o = map.get(TRANSACTIONNUMBER4)) != null) {
            if (o instanceof Double) {
                eeo.setTransactionnumber4((Double) o);
            } else {
                try {
                    eeo.setTransactionnumber4(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing transaction number 4", ex);
                }
            }
        }
        if ((o = map.get(TRANSACTIONNUMBER5)) != null) {
            if (o instanceof Double) {
                eeo.setTransactionnumber5((Double) o);
            } else {
                try {
                    eeo.setTransactionnumber5(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing transaction number 5", ex);
                }
            }
        }
        if ((o = map.get(CUSTOMSTRING1)) != null) {
            eeo.setCustomstring1((String) o);
        }
        if ((o = map.get(CUSTOMSTRING2)) != null) {
            eeo.setCustomstring2((String) o);
        }
        if ((o = map.get(CUSTOMSTRING3)) != null) {
            eeo.setCustomstring3((String) o);
        }
        if ((o = map.get(CUSTOMNUMBER1)) != null) {
            if (o instanceof Double) {
                eeo.setCustomnumber1((Double) o);
            } else {
                try {
                    eeo.setCustomnumber1(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing custom number 1", ex);
                }
            }
        }
        if ((o = map.get(CUSTOMNUMBER2)) != null) {
            if (o instanceof Double) {
                eeo.setCustomnumber2((Double) o);
            } else {
                try {
                    eeo.setCustomnumber2(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing custom number 2", ex);
                }
            }
        }
        if ((o = map.get(CUSTOMNUMBER3)) != null) {
            if (o instanceof Double) {
                eeo.setCustomnumber3((Double) o);
            } else {
                try {
                    eeo.setCustomnumber3(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing custom number 3", ex);
                }
            }
        }
        if ((o = map.get(BASEEVENTID)) != null) {
            eeo.setBaseeventid((String) o);
        }
        if ((o = map.get(BASEEVENTCOUNT)) != null) {
            if (o instanceof Integer) {
                eeo.setBaseeventcount((Integer) o);
            } else {
                try {
                    eeo.setBaseeventcount(Integer.parseInt((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing base event count", ex);
                }
            }
        }
        if ((o = map.get(EMAILSUBJECT)) != null) {
            eeo.setEmailsubject((String) o);
        }
        if ((o = map.get(EMAILSENDER)) != null) {
            eeo.setEmailsender((String) o);
        }
        if ((o = map.get(EMAILSENDERDOMAIN)) != null) {
            eeo.setEmailsenderdomain((String) o);
        }
        if ((o = map.get(EMAILRECIPIENT)) != null) {
            eeo.setEmailrecipient((String) o);
        }
        if ((o = map.get(EMAILRECIPIENTDOMAIN)) != null) {
            eeo.setEmailrecipientdomain((String) o);
        }
        if ((o = map.get(EMAILRECIPIENTTYPE)) != null) {
            eeo.setEmailrecipienttype((String) o);
        }
        if ((o = map.get(RESOURCECOMMENTS)) != null) {
            eeo.setResourcecomments((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD1)) != null) {
            eeo.setResourcecustomfield1((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD2)) != null) {
            eeo.setResourcecustomfield2((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD3)) != null) {
            eeo.setResourcecustomfield3((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD4)) != null) {
            eeo.setResourcecustomfield4((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD5)) != null) {
            eeo.setResourcecustomfield5((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD6)) != null) {
            eeo.setResourcecustomfield6((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD7)) != null) {
            eeo.setResourcecustomfield7((String) o);
        }
        if ((o = map.get(RESOURCECUSTOMFIELD8)) != null) {
            eeo.setResourcecustomfield8((String) o);
        }
        if ((o = map.get(RESOURCEHIERARCHY)) != null) {
            eeo.setResourcehierarchy((String) o);
        }
        if ((o = map.get(RESOURCEHIERARCHYNAME)) != null) {
            eeo.setResourcehierarchyname((String) o);
        }
        if ((o = map.get(RESOURCESTATUS)) != null) {
            eeo.setResourcestatus((String) o);
        }
        if ((o = map.get(RESOURCEHOSTNAME)) != null) {
            eeo.setResourcehostname((String) o);
        }

        if ((o = map.get(EVENTCOUNTRY)) != null) {
            eeo.setEventcountry((String) o);
        }
        if ((o = map.get(EVENTREGION)) != null) {
            eeo.setEventregion((String) o);
        }
        if ((o = map.get(EVENTCITY)) != null) {
            eeo.setEventcity((String) o);
        }
        if ((o = map.get(EVENTLATITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setEventlatitude((Double) o);
            } else {
                try {
                    eeo.setEventlatitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing event latitude", ex);
                }
            }
        }
        if ((o = map.get(EVENTLONGITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setEventlongitude((Double) o);
            } else {
                try {
                    eeo.setEventlongitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing event longitude", ex);
                }
            }
        }
        if ((o = map.get(POSTALCODE)) != null) {
            eeo.setPostalcode((String) o);
        }
        if ((o = map.get(SOURCEHOSTNAMECOUNTRY)) != null) {
            eeo.setSourcehostnamecountry((String) o);
        }
        if ((o = map.get(SOURCEHOSTNAMEREGION)) != null) {
            eeo.setSourcehostnameregion((String) o);
        }
        if ((o = map.get(SOURCEHOSTNAMECITY)) != null) {
            eeo.setSourcehostnamecity((String) o);
        }
        if ((o = map.get(SOURCEHOSTNAMELATITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setSourcehostnamelatitude((Double) o);
            } else {
                try {
                    eeo.setSourcehostnamelatitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing source hostname latitude", ex);
                }
            }
        }
        if ((o = map.get(SOURCEHOSTNAMELONGITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setSourcehostnamelongitude((Double) o);
            } else {
                try {
                    eeo.setSourcehostnamelongitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing source hostname longitude", ex);
                }
            }
        }
        if ((o = map.get(SOURCEHOSTNAMEPOSTALCODE)) != null) {
            eeo.setSourcehostnamepostalcode((String) o);
        }
        if ((o = map.get(DESTINATIONHOSTNAMECOUNTRY)) != null) {
            eeo.setDestinationhostnamecountry((String) o);
        }
        if ((o = map.get(DESTINATIONHOSTNAMEREGION)) != null) {
            eeo.setDestinationhostnameregion((String) o);
        }
        if ((o = map.get(DESTINATIONHOSTNAMECITY)) != null) {
            eeo.setDestinationhostnamecity((String) o);
        }
        if ((o = map.get(DESTINATIONHOSTNAMELATITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setDestinationhostnamelatitude((Double) o);
            } else {
                try {
                    eeo.setDestinationhostnamelatitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing destination hostname latitude", ex);
                }
            }
        }
        if ((o = map.get(DESTINATIONHOSTNAMELONGITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setDestinationhostnamelongitude((Double) o);
            } else {
                try {
                    eeo.setDestinationhostnamelongitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing destination hostname longitude", ex);
                }
            }
        }
        if ((o = map.get(DESTINATIONHOSTNAMEPOSTALCODE)) != null) {
            eeo.setDestinationhostnamepostalcode((String) o);
        }
        if ((o = map.get(RESOURCEHOSTNAMECOUNTRY)) != null) {
            eeo.setResourcehostnamecountry((String) o);
        }
        if ((o = map.get(RESOURCEHOSTNAMEREGION)) != null) {
            eeo.setResourcehostnameregion((String) o);
        }

        if ((o = map.get(RESOURCEHOSTNAMECITY)) != null) {
            eeo.setResourcehostnamecity((String) o);
        }
        if ((o = map.get(RESOURCEHOSTNAMELATITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setResourcehostnamelatitude((Double) o);
            } else {
                try {
                    eeo.setResourcehostnamelatitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing resource hostname latitude", ex);
                }
            }
        }
        if ((o = map.get(RESOURCEHOSTNAMELONGITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setResourcehostnamelongitude((Double) o);
            } else {
                try {
                    eeo.setResourcehostnamelongitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing resource hostname longitude", ex);
                }
            }
        }
        if ((o = map.get(RESOURCEHOSTNAMEPOSTALCODE)) != null) {
            eeo.setResourcehostnamepostalcode((String) o);
        }
        if ((o = map.get(DEVICEHOSTNAMECOUNTRY)) != null) {
            eeo.setDevicehostnamecountry((String) o);
        }
        if ((o = map.get(DEVICEHOSTNAMEREGION)) != null) {
            eeo.setDevicehostnameregion((String) o);
        }
        if ((o = map.get(DEVICEHOSTNAMECITY)) != null) {
            eeo.setDevicehostnamecity((String) o);
        }
        if ((o = map.get(DEVICEHOSTNAMELATITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setDevicehostnamelatitude((Double) o);
            } else {
                try {
                    eeo.setDevicehostnamelatitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing device hostname latitude", ex);
                }
            }
        }
        if ((o = map.get(DEVICEHOSTNAMELONGITUDE)) != null) {
            if (o instanceof Double) {
                eeo.setDevicehostnamelongitude((Double) o);
            } else {
                try {
                    eeo.setDevicehostnamelongitude(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing device hostname longitude", ex);
                }
            }
        }
        if ((o = map.get(DEVICEHOSTNAMEPOSTALCODE)) != null) {
            eeo.setDevicehostnamepostalcode((String) o);
        }

        if ((o = map.get(TPI_ADDR)) != null) {
            eeo.setTpi_addr((String) o);
        }
        if ((o = map.get(TPI_DOMAIN)) != null) {
            eeo.setTpi_domain((String) o);
        }
        if ((o = map.get(TPI_TYPE)) != null) {
            eeo.setTpi_type((String) o);
        }
        if ((o = map.get(TPI_SRC)) != null) {
            eeo.setTpi_src((String) o);
        }
        if ((o = map.get(TPI_DATE)) != null) {
            if (o instanceof Long) {
                eeo.setTpi_date((Long) o);
            } else {
                try {
                    eeo.setTpi_date(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing TPI date", ex);
                }
            }
        }
        if ((o = map.get(TPI_TEXT)) != null) {
            eeo.setTpi_text((String) o);
        }
        if ((o = map.get(TPI_CATEGORY)) != null) {
            eeo.setTpi_category((String) o);
        }
        if ((o = map.get(TPI_REASON)) != null) {
            eeo.setTpi_reason((String) o);
        }
        if ((o = map.get(TPI_DESCRIPTION)) != null) {
            eeo.setTpi_description((String) o);
        }
        if ((o = map.get(TPI_FILENAME)) != null) {
            eeo.setTpi_filename((String) o);
        }
        if ((o = map.get(TPI_ACTION)) != null) {
            eeo.setTpi_action((String) o);
        }
        if ((o = map.get(TPI_CRITICALITY)) != null) {
            if (o instanceof Double) {
                eeo.setTpi_criticality((Double) o);
            } else {
                try {
                    eeo.setTpi_criticality(Double.parseDouble((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing TPI criticality", ex);
                }
            }
        }
        if ((o = map.get(TPI_VERSION)) != null) {
            if (o instanceof Long) {
                eeo.setTpi_version((Long) o);
            } else {
                try {
                    eeo.setTpi_version(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing TPI version", ex);
                }
            }
        }
        if ((o = map.get(TPI_MALWARE)) != null) {
            eeo.setTpi_malware((String) o);
        }
        if ((o = map.get(TPI_RISK)) != null) {
            eeo.setTpi_risk((String) o);
        }
        if ((o = map.get(TPI_RECOMMENDATION)) != null) {
            eeo.setTpi_recommendation((String) o);
        }
        if ((o = map.get(TPI_RESOLUTION)) != null) {
            eeo.setTpi_resolution((String) o);
        }
        if ((o = map.get(TPI_INDICATORS)) != null) {
            eeo.setTpi_indicators((String) o);
        }

        if ((o = map.get(ACCOUNTCRITICALITY)) != null) {
            eeo.setAccountcriticality((String) o);
        }
        if ((o = map.get(ACCOUNTTYPE)) != null) {
            eeo.setAccounttype((String) o);
        }
        if ((o = map.get(ACCOUNTCREATEDDATE)) != null) {
            if (o instanceof Long) {
                eeo.setAccountcreateddate((Long) o);
            } else {
                try {
                    eeo.setAccountcreateddate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing account created date", ex);
                }
            }
        }
        if ((o = map.get(ACCOUNTDISABLEDDATE)) != null) {
            if (o instanceof Long) {
                eeo.setAccountdisableddate((Long) o);
            } else {
                try {
                    eeo.setAccountdisableddate(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing account disabled date", ex);
                }
            }
        }
        if ((o = map.get(ACCOUNTWHITELISTED)) != null) {
            if (o instanceof Boolean) {
                eeo.setAccountwhitelisted((Boolean) o);
            } else {
                try {
                    eeo.setAccountwhitelisted(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing account whitelisted flag", ex);
                }
            }
        }
        if ((o = map.get(ACCOUNTBLACKLISTED)) != null) {
            if (o instanceof Boolean) {
                eeo.setAccountblacklisted((Boolean) o);
            } else {
                try {
                    eeo.setAccountblacklisted(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing account blacklisted flag", ex);
                }
            }
        }
        if ((o = map.get(ACCOUNTENCRYPTED)) != null) {
            if (o instanceof Boolean) {
                eeo.setAccountencrypted((Boolean) o);
            } else {
                try {
                    eeo.setAccountencrypted(Boolean.parseBoolean((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing account encrypted flag", ex);
                }
            }
        }
        if ((o = map.get(ACCOUNTOWNER)) != null) {
            eeo.setAccountowner((String) o);
        }
        if ((o = map.get(ACCOUNTSTATUS)) != null) {
            eeo.setAccountstatus((String) o);
        }

        if ((o = map.get(CATEGORYOUTCOME)) != null) {
            eeo.setCategoryoutcome((String) o);
        }
        if ((o = map.get(CATEGORYSEVERITY)) != null) {
            eeo.setCategoryseverity((String) o);
        }

        if ((o = map.get(TENANTNAME)) != null) {
            eeo.setTenantname((String) o);
        }
        if ((o = map.get(TENANTTZ)) != null) {
            eeo.setTenantTz((String) o);
        }
        if ((o = map.get(TENANTID)) != null) {
            eeo.setTenantid(Long.parseLong((String) o));
        }

        if ((o = map.get(OLDFILEPERMISSION)) != null) {
            eeo.setOldfilepermission((String) o);
        }
        if ((o = map.get(OLDFILEHASH)) != null) {
            eeo.setOldfilehash((String) o);
        }
        if ((o = map.get(OLDFILECREATETIME)) != null) {
            if (o instanceof Long) {
                eeo.setOldfilecreatetime((Long) o);
            } else {
                try {
                    eeo.setOldfilecreatetime(Long.parseLong((String) o));
                } catch (NumberFormatException ex) {
                    LOGGER.warn("Error parsing old file create time", ex);
                }
            }
        }
        if ((o = map.get(DEVICEEXTERNALID)) != null) {
            eeo.setDeviceexternalid((String) o);
        }
    }

}
