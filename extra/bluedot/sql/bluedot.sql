--
-- Table structure for table `q_filename_rep`
--

DROP TABLE IF EXISTS `q_filename_rep`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `q_filename_rep` (
  `filename` varchar(255) DEFAULT NULL,
  `reputation` int(11) DEFAULT NULL,
  `s_id` mediumint(8) unsigned DEFAULT NULL,
  `fingerprint` varchar(100) DEFAULT NULL,
  `comments` varchar(1024) DEFAULT NULL,
  `rep_source` varchar(128) DEFAULT NULL,
  `rep_published` datetime DEFAULT NULL,
  `rep_last_status` datetime DEFAULT NULL,
  KEY `filename` (`filename`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `q_hash_rep`
--

DROP TABLE IF EXISTS `q_hash_rep`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `q_hash_rep` (
  `hash` varchar(256) DEFAULT NULL,
  `reputation` int(11) DEFAULT NULL,
  `s_id` mediumint(8) unsigned DEFAULT NULL,
  `fingerprint` varchar(200) DEFAULT NULL,
  `comments` varchar(1024) DEFAULT NULL,
  `rep_source` varchar(128) DEFAULT NULL,
  `rep_published` datetime DEFAULT NULL,
  `rep_last_status` datetime DEFAULT NULL,
  KEY `hash` (`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `q_ip_rep`
--

DROP TABLE IF EXISTS `q_ip_rep`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `q_ip_rep` (
  `ip_address` varchar(46) DEFAULT NULL,
  `reputation` int(11) DEFAULT NULL,
  `s_id` mediumint(8) unsigned DEFAULT NULL,
  `fingerprint` varchar(100) DEFAULT NULL,
  `comments` varchar(1024) DEFAULT NULL,
  `rep_source` varchar(128) DEFAULT NULL,
  `rep_published` datetime DEFAULT NULL,
  `rep_last_status` datetime DEFAULT NULL,
  KEY `ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `q_ja3_rep`
--

DROP TABLE IF EXISTS `q_ja3_rep`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `q_ja3_rep` (
  `ja3` varchar(32) DEFAULT NULL,
  `reputation` int(11) DEFAULT NULL,
  `s_id` mediumint(8) unsigned DEFAULT NULL,
  `fingerprint` varchar(100) DEFAULT NULL,
  `comments` varchar(1024) DEFAULT NULL,
  `rep_source` varchar(128) DEFAULT NULL,
  `rep_published` datetime DEFAULT NULL,
  `rep_last_status` datetime DEFAULT NULL,
  KEY `ja3` (`ja3`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `q_url_rep`
--

DROP TABLE IF EXISTS `q_url_rep`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `q_url_rep` (
  `url` varchar(10000) DEFAULT NULL,
  `reputation` int(11) DEFAULT NULL,
  `s_id` mediumint(8) unsigned DEFAULT NULL,
  `fingerprint` varchar(200) DEFAULT NULL,
  `comments` varchar(1024) DEFAULT NULL,
  `rep_source` varchar(128) DEFAULT NULL,
  `rep_published` datetime DEFAULT NULL,
  `rep_last_status` datetime DEFAULT NULL,
  KEY `url` (`url`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

