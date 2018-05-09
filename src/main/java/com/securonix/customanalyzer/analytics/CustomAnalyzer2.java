/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securonix.customanalyzer.analytics;

import com.securonix.redis.RedisClient;
import com.securonix.snyper.config.beans.RedisConfigBean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author manishkumar
 */
public class CustomAnalyzer2 {

    private final RedisClient redisClient = RedisClient.INSTANCE;

    private final static Logger LOGGER = LogManager.getLogger();
    
    /**
     * Redis Client gets initialized.
     * 
     * @param redisConfigben  Redis Configuration Bean
    */

    public void init(RedisConfigBean redisConfigben) {
        try {
            redisClient.initialize(redisConfigben);
            LOGGER.debug("Redis client obtained!");

        } catch (Exception ex) {
            LOGGER.error("Error while obtaining Redis Client ", ex);
        }

    }
    
    /**
     * Check for Redis Key
     * 
     * @param key : Redis Key
     * @return true if key present,else false.
     */

    public boolean isKeyPresentInRedis(String key) {
        if (redisClient.isPresent(key)) {
            LOGGER.info("Key[" + key + "] found in Redis Memory");
            return true;

        } else {
            LOGGER.info("Key[" + key + "] not found in Redis Memory");
            return false;
        }

    }
}
