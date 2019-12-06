-- DDL for SignServer 4.0.x on Postgres
-- Version: $Id$


--
-- Name: auditrecorddata; Type: TABLE; Schema: public; Owner: signserver; Tablespace: 
--

CREATE TABLE auditrecorddata (
    pk text NOT NULL,
    additionaldetails text,
    authtoken text NOT NULL,
    customid text,
    eventstatus text NOT NULL,
    eventtype text NOT NULL,
    module text NOT NULL,
    nodeid text NOT NULL,
    rowprotection text,
    rowversion int4 NOT NULL,
    searchdetail1 text,
    searchdetail2 text,
    sequencenumber int8 NOT NULL,
    service text NOT NULL,
    "timestamp" int8 NOT NULL
);

--
-- Name: globalconfigdata; Type: TABLE; Schema: public; Owner: signserver; Tablespace: 
--

CREATE TABLE globalconfigdata (
    propertykey character varying(255) NOT NULL,
    propertyvalue text
);

--
-- Name: signerconfigdata; Type: TABLE; Schema: public; Owner: signserver; Tablespace: 
--

CREATE TABLE signerconfigdata (
    signerid integer NOT NULL,
    signername character varying(255),
    signertype integer,
    signerconfigdata text
);


--
-- Name: keyusagecounter; Type: TABLE; Schema: public; Owner: signserver; Tablespace: 
--

CREATE TABLE keyusagecounter (
    keyhash character varying(255) NOT NULL,
    counter bigint NOT NULL
);


--
-- Name: archivedata; Type: TABLE; Schema: public; Owner: signserver; Tablespace: 
--

CREATE TABLE archivedata (
    uniqueid character varying(255) NOT NULL,
    archivedata text,
    archiveid character varying(255),
    dataencoding integer,
    requestcertserialnumber character varying(255),
    requestip character varying(255),
    requestissuerdn character varying(255),
    signerid integer NOT NULL,
    "time" bigint NOT NULL,
    type integer NOT NULL
);


--
-- Table structure for table `KeyData`
--
CREATE TABLE KeyData (
  keyAlias character varying(255) NOT NULL,
  wrappingKeyAlias character varying(255) NOT NULL,
  wrappingCipher bigint NOT NULL,
  keyData text NOT NULL,
  certData text NOT NULL 
); 


--
-- Name: hibernate_sequence; Type: SEQUENCE; Schema: public; Owner: signserver
--

CREATE SEQUENCE hibernate_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



--
-- Name: archivedata_pkey; Type: CONSTRAINT; Schema: public; Owner: signserver; Tablespace: 
--

ALTER TABLE ONLY archivedata
    ADD CONSTRAINT archivedata_pkey PRIMARY KEY (uniqueid);

--
-- Name: auditrecorddata_pkey; Type: CONSTRAINT; Schema: public; Owner: signserver; Tablespace: 
--

ALTER TABLE ONLY auditrecorddata
    ADD CONSTRAINT auditrecorddata_pkey PRIMARY KEY (pk);

--
-- Name: globalconfigdata_pkey; Type: CONSTRAINT; Schema: public; Owner: signserver; Tablespace: 
--

ALTER TABLE ONLY globalconfigdata
    ADD CONSTRAINT globalconfigdata_pkey PRIMARY KEY (propertykey);

--
-- Name: keyusagecounter_pkey; Type: CONSTRAINT; Schema: public; Owner: signserver; Tablespace: 
--

ALTER TABLE ONLY keyusagecounter
    ADD CONSTRAINT keyusagecounter_pkey PRIMARY KEY (keyhash);


--
-- Name: signerconfigdata_pkey; Type: CONSTRAINT; Schema: public; Owner: signserver; Tablespace: 
--

ALTER TABLE ONLY signerconfigdata
    ADD CONSTRAINT signerconfigdata_pkey PRIMARY KEY (signerid);

--
-- Name: keydata_pkey; Type: CONSTRAINT; Schema: public; Owner: signserver; Tablespace: 
--

ALTER TABLE ONLY KeyData
    ADD CONSTRAINT keydata_pkey PRIMARY KEY (keyAlias);

