package com.securonix.customanalyzer.analytics;

import com.securonix.application.impala.ImpalaDbUtil;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Custom analyzer 
 * 
 * @author Securonix Inc.
 */
public class CustomAnalyzer1 {
    
    private final static Logger LOGGER = LogManager.getLogger();
    
    /**
     * Forms the queries based on resource group Id
     *
     * @param rgId Resource group Id
     * @return List of queries formed for the given resource group
     */
    public static List<String> formQueries(final long rgId) {

        LOGGER.debug("Forming queries for RgId: {}", rgId);
        final List<String> queries = new ArrayList<>();

        final String violationQuery = "select ipaddress, accountname, year, dayofyear, hour, minute from activity" + rgId + "incoming where message='Logon Failed' group by accountname, ipaddress, year, dayofyear, hour, minute having count(accountname) > 5";

        // PERFORM ANALYTICS HERE
        List<HashMap<String, Object>> violationEvents = null;
        try {
            violationEvents = ImpalaDbUtil.executeQuery(violationQuery);
        } catch (Exception ex) {
            LOGGER.error("Error getting results from HDFS", ex);
        }

        LOGGER.debug("Base query violation count # {}", (violationEvents == null ? 0 : violationEvents.size()));
        if (violationEvents != null && !violationEvents.isEmpty()) {

            String query;
            for (HashMap<String, Object> violationEvent : violationEvents) {

                String account = (String) violationEvent.get("accountname");
                String srcip = (String) violationEvent.get("ipaddress");
                String year = (String) violationEvent.get("year");
                String dayofyear = (String) violationEvent.get("dayofyear");
                String hour = (String) violationEvent.get("hour");
                String minute = (String) violationEvent.get("minute");

                query = "select * from activity" + rgId + "incoming where message='Logon Failed' and accountname='" + account + "' and ipaddress='" + srcip + "' and year=" + year + " and dayofyear=" + dayofyear + " and hour =" + hour + " and minute=" + minute;
                queries.add(query);
            }

        } else {
            LOGGER.info("No Violation found");
        }

        LOGGER.debug("Returning queries # {}", queries.size());
        return queries;
    }

}
