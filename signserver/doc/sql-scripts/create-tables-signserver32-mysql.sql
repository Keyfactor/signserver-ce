-- TODO: Remove this file

-- MySQL dump 10.13  Distrib 5.1.41, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: signserver
-- ------------------------------------------------------
-- Server version	5.1.41-3ubuntu12.7

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `ArchiveData`
--

DROP TABLE IF EXISTS `ArchiveData`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ArchiveData` (
  `uniqueId` varchar(255) NOT NULL,
  `time` bigint(20) NOT NULL,
  `type` int(11) NOT NULL,
  `signerid` int(11) NOT NULL,
  `archiveid` varchar(255) DEFAULT NULL,
  `requestIssuerDN` varchar(255) DEFAULT NULL,
  `requestCertSerialnumber` varchar(255) DEFAULT NULL,
  `requestIP` varchar(255) DEFAULT NULL,
  `archiveData` mediumtext,
  PRIMARY KEY (`uniqueId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BOOKDATABEAN`
--

DROP TABLE IF EXISTS `BOOKDATABEAN`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `BOOKDATABEAN` (
  `NAME` varchar(255) NOT NULL,
  `COUNTER` int(11) DEFAULT NULL,
  PRIMARY KEY (`NAME`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `BookDataBean`
--

DROP TABLE IF EXISTS `BookDataBean`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `BookDataBean` (
  `name` varchar(255) NOT NULL,
  `counter` int(11) NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ClusterClassLoaderData`
--

DROP TABLE IF EXISTS `ClusterClassLoaderData`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ClusterClassLoaderData` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `resourceName` varchar(255) NOT NULL,
  `implInterfaces` text NOT NULL,
  `version` int(11) NOT NULL,
  `type` varchar(255) NOT NULL,
  `jarName` varchar(255) NOT NULL,
  `moduleName` varchar(255) NOT NULL,
  `part` varchar(255) NOT NULL,
  `resourceData` mediumblob NOT NULL,
  `timeStamp` bigint(20) NOT NULL,
  `description` text,
  `comment` text,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=292 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `GlobalConfigurationData`
--

DROP TABLE IF EXISTS `GlobalConfigurationData`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `GlobalConfigurationData` (
  `propertyKey` varchar(255) NOT NULL,
  `propertyValue` mediumtext,
  PRIMARY KEY (`propertyKey`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `KeyUsageCounter`
--

DROP TABLE IF EXISTS `KeyUsageCounter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `KeyUsageCounter` (
  `keyHash` varchar(255) NOT NULL,
  `counter` bigint(20) NOT NULL,
  PRIMARY KEY (`keyHash`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SEQUENCE`
--

DROP TABLE IF EXISTS `SEQUENCE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SEQUENCE` (
  `SEQ_NAME` varchar(50) NOT NULL,
  `SEQ_COUNT` decimal(38,0) DEFAULT NULL,
  PRIMARY KEY (`SEQ_NAME`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SHELFDATABEAN`
--

DROP TABLE IF EXISTS `SHELFDATABEAN`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SHELFDATABEAN` (
  `NAME` varchar(255) NOT NULL,
  `COUNTER` int(11) DEFAULT NULL,
  PRIMARY KEY (`NAME`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ShelfDataBean`
--

DROP TABLE IF EXISTS `ShelfDataBean`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ShelfDataBean` (
  `name` varchar(255) NOT NULL,
  `counter` int(11) NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAAliases`
--

DROP TABLE IF EXISTS `WSRAAliases`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAAliases` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userId` int(11) NOT NULL,
  `type` varchar(255) NOT NULL,
  `alias` varchar(255) NOT NULL,
  `comment` text,
  PRIMARY KEY (`id`),
  KEY `FKD856467336FAF01B` (`userId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAAuthData`
--

DROP TABLE IF EXISTS `WSRAAuthData`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAAuthData` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `authType` int(11) NOT NULL,
  `authValue` text NOT NULL,
  `userId` int(11) NOT NULL,
  `comment` text,
  PRIMARY KEY (`id`),
  KEY `FK219D249D36FAF01B` (`userId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRACertificates`
--

DROP TABLE IF EXISTS `WSRACertificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRACertificates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `fingerprint` varchar(255) NOT NULL,
  `tokenId` int(11) NOT NULL,
  `type` int(11) NOT NULL,
  `profile` varchar(255) NOT NULL,
  `issuerDN` varchar(255) NOT NULL,
  `subjectDN` varchar(255) NOT NULL,
  `serialNumber` varchar(255) NOT NULL,
  `expireDate` bigint(20) NOT NULL,
  `certificateData` blob,
  `comment` text,
  `status` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `FKD4595B673902CFD7` (`tokenId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRADataBank`
--

DROP TABLE IF EXISTS `WSRADataBank`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRADataBank` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` int(11) NOT NULL,
  `relatedId` int(11) NOT NULL,
  `theKey` varchar(255) NOT NULL,
  `theValue` text,
  `theComment` text,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAOrganizations`
--

DROP TABLE IF EXISTS `WSRAOrganizations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAOrganizations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` int(11) NOT NULL,
  `status` int(11) NOT NULL,
  `organizationName` varchar(255) NOT NULL,
  `displayName` varchar(255) NOT NULL,
  `comment` text,
  `allowedIssuersData` text NOT NULL,
  `allowedCProfilesData` text NOT NULL,
  `allowedTProfilesData` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAPricing`
--

DROP TABLE IF EXISTS `WSRAPricing`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAPricing` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `priceClass` varchar(255) NOT NULL,
  `displayName` varchar(255) NOT NULL,
  `price` float NOT NULL,
  `currency` varchar(255) NOT NULL,
  `comment` text,
  `status` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAProdInOrg`
--

DROP TABLE IF EXISTS `WSRAProdInOrg`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAProdInOrg` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `organizationId` int(11) NOT NULL,
  `priceId` int(11) NOT NULL,
  `productId` int(11) NOT NULL,
  `currency` varchar(255) NOT NULL,
  `comment` text,
  `productNumber` varchar(255) DEFAULT NULL,
  `priceClass` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK7B5FB49DB20C0EB` (`organizationId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAProduct`
--

DROP TABLE IF EXISTS `WSRAProduct`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAProduct` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `productNumber` varchar(255) NOT NULL,
  `displayName` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `comment` text,
  `status` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRATokens`
--

DROP TABLE IF EXISTS `WSRATokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRATokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `organizationId` int(11) NOT NULL,
  `userId` int(11) NOT NULL,
  `copyOf` int(11) DEFAULT NULL,
  `profile` varchar(255) NOT NULL,
  `serialNumber` varchar(255) NOT NULL,
  `sensitiveData` blob,
  `comment` text,
  PRIMARY KEY (`id`),
  KEY `FK61604B8536FAF01B` (`userId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRATrans`
--

DROP TABLE IF EXISTS `WSRATrans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRATrans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `organizationId` int(11) NOT NULL,
  `productId` int(11) NOT NULL,
  `units` int(11) NOT NULL,
  `transactionDate` bigint(20) NOT NULL,
  `expectedLifeDate` bigint(20) NOT NULL,
  `comment` text,
  `status` int(11) NOT NULL,
  `nodeId` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WSRAUsers`
--

DROP TABLE IF EXISTS `WSRAUsers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WSRAUsers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userName` varchar(255) NOT NULL,
  `clearPassword` bit(1) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `displayName` varchar(255) NOT NULL,
  `rolesData` text NOT NULL,
  `comment` text,
  `status` int(11) NOT NULL,
  `organizationId` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `FK76D0DEBDB20C0EB` (`organizationId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `enckeydata`
--

DROP TABLE IF EXISTS `enckeydata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `enckeydata` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `workerId` int(11) NOT NULL,
  `encKeyRef` varchar(255) DEFAULT NULL,
  `inUse` bit(1) NOT NULL,
  `usageStarted` datetime DEFAULT NULL,
  `usageEnded` datetime DEFAULT NULL,
  `numberOfEncryptions` bigint(20) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=122 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `groupkeydata`
--

DROP TABLE IF EXISTS `groupkeydata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `groupkeydata` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `documentID` varchar(255) DEFAULT NULL,
  `workerId` int(11) NOT NULL,
  `encryptedData` blob,
  `creationDate` datetime DEFAULT NULL,
  `firstUsedDate` datetime DEFAULT NULL,
  `lastFetchedDate` datetime DEFAULT NULL,
  `encKeyRef` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=128 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `signerconfigdata`
--

DROP TABLE IF EXISTS `signerconfigdata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `signerconfigdata` (
  `signerId` int(11) NOT NULL,
  `signerConfigData` mediumtext,
  PRIMARY KEY (`signerId`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2010-11-16 10:17:48
