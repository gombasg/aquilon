ALTER TABLE clstr RENAME CONSTRAINT cluster_pk TO clstr_pk;
ALTER INDEX cluster_pk RENAME TO clstr_pk;
ALTER TABLE esx_cluster RENAME CONSTRAINT esx_cluster_fk TO esx_cluster_cluster_fk;
ALTER TABLE fqdn DROP CONSTRAINT fqdn_name_domain_env_uk DROP INDEX;
ALTER TABLE fqdn ADD CONSTRAINT fqdn_domain_name_env_uk UNIQUE (dns_domain_id, name, dns_environment_id);
ALTER TABLE hardware_entity ADD CONSTRAINT hw_ent_pri_name_uk UNIQUE (primary_name_id);
ALTER INDEX hw_ent_loc_idx RENAME TO hw_ent_location_idx;
ALTER TABLE hardware_entity RENAME CONSTRAINT hw_ent_loc_fk TO hw_ent_location_fk;
ALTER TABLE host DROP CONSTRAINT host_machine_branch_uk DROP INDEX;
ALTER TABLE interface DROP CONSTRAINT iface_vlan_ck;
ALTER TABLE interface ADD CONSTRAINT iface_vlan_ck CHECK (parent_id IS NOT NULL AND vlan_id > 0 AND vlan_id < 4096 OR interface_type != 'vlan');
ALTER TABLE machine_specs RENAME CONSTRAINT machine_specs_cr_date_nn TO mchn_specs_cr_date_nn;
ALTER TABLE model DROP CONSTRAINT model_name_vendor_uk DROP INDEX;
ALTER TABLE model ADD CONSTRAINT model_vendor_name_uk UNIQUE (vendor_id, name);
ALTER INDEX network_loc_id_idx RENAME TO network_location_idx;
ALTER TABLE observed_vlan DROP CONSTRAINT observed_vlan_max_vlan_id_ck;
ALTER TABLE observed_vlan DROP CONSTRAINT observed_vlan_min_vlan_id_ck;
ALTER TABLE observed_vlan ADD CONSTRAINT observed_vlan_vlan_id_ck CHECK (vlan_id >= 0 AND vlan_id < 4096);
ALTER TABLE operating_system RENAME CONSTRAINT os_pk TO operating_system_pk;
ALTER INDEX os_pk RENAME TO operating_system_pk;
ALTER TABLE operating_system DROP CONSTRAINT operating_system_uk DROP INDEX;
ALTER TABLE operating_system ADD CONSTRAINT os_arch_name_version_uk UNIQUE (archetype_id, name, version);
ALTER TABLE personality RENAME CONSTRAINT prsnlty_pk TO personality_pk;
ALTER INDEX prsnlty_pk RENAME TO personality_pk;
ALTER TABLE personality DROP CONSTRAINT personality_uk DROP INDEX;
ALTER TABLE personality ADD CONSTRAINT personality_arch_name_uk UNIQUE (archetype_id, name);
DROP INDEX prsnlty_arch_idx;
ALTER TABLE personality_service_map RENAME CONSTRAINT prsnlty_svc_map_pk TO personality_service_map_pk;
ALTER INDEX prsnlty_svc_map_pk RENAME TO personality_service_map_pk;
ALTER TABLE "resource" RENAME CONSTRAINT resource_holder_id_nn TO "resource_HOLDER_ID_NN";
ALTER TABLE service_instance RENAME CONSTRAINT svc_inst_pk TO service_instance_pk;
ALTER INDEX svc_inst_pk RENAME TO service_instance_pk;
ALTER TABLE "resource" RENAME CONSTRAINT resource_holder_id_nn TO "resource_HOLDER_ID_NN";
ALTER TABLE resholder ADD CONSTRAINT resholder_rg_uk UNIQUE (resourcegroup_id);
ALTER TABLE router_address DROP PRIMARY KEY DROP INDEX;
ALTER TABLE router_address ADD CONSTRAINT router_address_pk PRIMARY KEY (network_id, ip);
ALTER TABLE "share" RENAME CONSTRAINT "share_PK" TO share_pk;
ALTER TABLE "share" RENAME CONSTRAINT "share_RESOURCE_FK" TO share_resource_fk;
ALTER INDEX "share_PK" RENAME TO share_pk;
ALTER TABLE vlan_info DROP CONSTRAINT vlan_info_max_vlan_id_ck;
ALTER TABLE vlan_info DROP CONSTRAINT vlan_info_min_vlan_id_ck;
ALTER TABLE vlan_info ADD CONSTRAINT vlan_info_vlan_id_ck CHECK (vlan_id >= 0 AND vlan_id < 4096);
ALTER TABLE xtn_detail RENAME CONSTRAINT xtn_dtl_pk TO xtn_detail_pk;
ALTER INDEX xtn_dtl_pk RENAME TO xtn_detail_pk;

QUIT;
