-- QA fixture schema for the turbopuffer Powerpipe mod.
-- Mimics only the columns the 16 controls reference.
drop table if exists turbopuffer_document;
drop table if exists turbopuffer_namespace_attribute;
drop table if exists turbopuffer_namespace;

create table turbopuffer_namespace (
  id                    text primary key,
  region                text,
  approx_row_count      bigint,
  approx_logical_bytes  bigint,
  created_at            timestamptz,
  updated_at            timestamptz,
  index_unindexed_bytes bigint,
  index_status          text,
  encryption_key_name   text
);

create table turbopuffer_namespace_attribute (
  namespace          text,
  region             text,
  name               text,
  type               text,
  filterable         boolean,
  full_text_search   boolean,
  regex              boolean,
  glob               boolean,
  fuzzy              boolean
);

create table turbopuffer_document (
  namespace text,
  region    text,
  id        text
);

insert into turbopuffer_namespace values
  -- healthy multi-tenant namespace
  ('prod-tenant-a','gcp-us-central1',100,1073741824,now()-interval '100 days',now()-interval '1 day',0,'up-to-date',null),
  -- EU-tagged but in a US region
  ('pub-eu-data','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  -- missing ACL attr + search-amplified sensitive attr + no CMEK
  ('prod-tenant-b','gcp-us-central1',50,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  -- no ACL attribute at all
  ('prod-noacl','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  -- old empty namespace in an unapproved region
  ('empty-old','aws-eu-central-1',0,0,now()-interval '100 days',now()-interval '100 days',0,'up-to-date',null),
  -- stale namespace
  ('stale-1','gcp-us-central1',10,1073741824,now()-interval '400 days',now()-interval '200 days',0,'up-to-date',null),
  -- oversized namespace
  ('big-ns','gcp-us-central1',10,322122547200,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  -- bad naming convention
  ('Bad_Name','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  -- index lag
  ('lagging','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',4096,'updating',null),
  -- CMEK present but unapproved key
  ('prod-enc','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date','projects/x/locations/y/keyRings/z/cryptoKeys/unapproved'),
  -- schema drift pair (drift) and matched pair (no drift)
  ('prod-drift','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  ('staging-drift','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  ('prod-same','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null),
  ('staging-same','gcp-us-central1',10,1073741824,now()-interval '10 days',now()-interval '1 day',0,'up-to-date',null);

insert into turbopuffer_namespace_attribute values
  ('prod-tenant-a','gcp-us-central1','tenant_id','string',true ,false,false,false,false),
  ('prod-tenant-a','gcp-us-central1','body','string'     ,false,true ,false,false,false),
  ('prod-noacl','gcp-us-central1','body','string',false,true,false,false,false),
  ('prod-tenant-b','gcp-us-central1','card_number','string',true,true,false,false,false),
  ('prod-tenant-b','gcp-us-central1','tenant_id','string',false,false,false,false,false),
  ('empty-old','aws-eu-central-1','tenant_id','string',true,false,false,false,false),
  ('stale-1','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('big-ns','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('Bad_Name','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('lagging','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('prod-enc','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('prod-drift','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('staging-drift','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('staging-drift','gcp-us-central1','ssn','string',true,false,false,false,false),
  ('prod-same','gcp-us-central1','tenant_id','string',true,false,false,false,false),
  ('staging-same','gcp-us-central1','tenant_id','string',true,false,false,false,false);

insert into turbopuffer_document values
  ('prod-tenant-a','gcp-us-central1','canary-1');
