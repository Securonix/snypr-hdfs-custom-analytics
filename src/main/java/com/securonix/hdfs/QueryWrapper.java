package com.securonix.hdfs;

import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import java.io.Serializable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Wrapper used to broadcast and obtain query processor on the executor
 *
 * @author Securonix Inc.
 */
public class QueryWrapper implements Serializable {

    /**
     * Query processor
     */
    private QueryProcessor processor;

    /**
     * Initializes and return query processor
     *
     * @param hcb Hadoop configuration
     * @param policy Policy configuration
     *
     * @return Query processor
     */
    public QueryProcessor getProcessor(final HadoopConfigBean hcb, final PolicyMaster policy) {

        if (processor == null) {
            processor = new QueryProcessor(hcb, policy);
        }

        return processor;
    }
}
