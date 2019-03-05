#
# (C) Copyright 2004-2006
# Wolfgang Denk, DENX Software Engineering, wd@denx.de.
#
# SPDX-License-Identifier:	GPL-2.0+
#

# core
ifndef CONFIG_SPL_BUILD
obj-y += init/
obj-y += main.o
obj-y += exports.o
obj-y += hash.o
obj-$(CONFIG_HUSH_PARSER) += cli_hush.o
obj-$(CONFIG_AUTOBOOT) += autoboot.o
obj-y += a_bitstr.o a_d2i_fp.o a_digest.o a_dup.o aes_cbc.o aes_cfb.o aes_core.o aes_ecb.o aes_ige.o aes_locl.h aes_misc.o aes_ofb.o aes_wrap.o aes_x86core.o a_gentm.o a_i2d_fp.o a_int.o a_mbstr.o ameth_lib.o a_object.o a_octet.o a_print.o aria.o arm_arch.h armcap.o a_sign.o asn1_err.o asn1_gen.o asn1_item_list.o asn1_item_list.h asn1_lib.o asn1_locl.h asn1_par.o asn_mime.o asn_moid.o asn_mstbl.o asn_pack.o a_strex.o a_strnid.o async.o async_err.o async_locl.h async_wait.o a_time.o a_type.o a_utctm.o a_utf8.o a_verify.o b_addr.o b_dump.o bf_buff.o bf_cfb64.o bf_ecb.o bf_enc.o bf_lbuf.o bf_locl.h bf_nbio.o bf_null.o bf_ofb64.o bf_pi.h bf_skey.o bio_asn1.o bio_b64.o bio_cb.o bio_enc.o bio_err.o bio_lcl.h bio_lib.o bio_md.o bio_meth.o bio_ndef.o bio_ok.o bio_pk7.o blake2b.o blake2b_mac.o blake2_impl.h blake2_locl.h blake2s.o blake2s_mac.o bn_add.o bn_asm.o bn_blind.o bn_const.o bn_ctx.o bn_depr.o bn_dh.o bn_div.o bn_err.o bn_exp2.o bn_exp.o bn_gcd.o bn_gf2m.o bn_intern.o bn_kron.o bn_lcl.h bn_lib.o bn_mod.o bn_mont.o bn_mpi.o bn_mul.o bn_nist.o bn_prime.o bn_prime.h bn_print.o bn_rand.o bn_recp.o bn_shift.o bn_sqr.o bn_sqrt.o bn_srp.o bn_word.o bn_x931p.o b_print.o b_sock2.o b_sock.o bss_acpt.o bss_bio.o bss_conn.o bss_dgram.o bss_fd.o bss_file.o bss_log.o bss_mem.o bss_null.o bss_sock.o buf_err.o buffer.o build.info by_dir.o by_file.o c_allc.o c_alld.o c_allm.o camellia.o cast_lcl.h cast_s.h cbc128.o cbc_cksm.o cbc_enc.o c_cfb64.o ccm128.o c_ecb.o c_enc.o cfb128.o cfb64ede.o cfb64enc.o cfb_enc.o chacha_enc.o charmap.h cmac.o cm_ameth.o cmeth_lib.o cmll_cbc.o cmll_cfb.o cmll_ctr.o cmll_ecb.o cmll_locl.h cmll_misc.o cmll_ofb.o cm_meth.o cms_asn1.o cms_att.o cms_cd.o cms_dd.o cms_enc.o cms_env.o cms_err.o cms_ess.o cms_io.o cms_kari.o cms_lcl.h cms_lib.o cms_pwri.o cms_sd.o cms_smime.o c_ofb64.o comp_err.o comp_lcl.h comp_lib.o conf_api.o conf_def.o conf_def.h conf_err.o conf_lcl.h conf_lib.o conf_mall.o conf_mod.o conf_sap.o conf_ssl.o context.o cpt_err.o cryptlib.o c_skey.o ct_b64.o ct_err.o ct_locl.h ct_log.o ct_oct.o ct_policy.o ct_prn.o ctr128.o cts128.o ct_sct.o ct_sct_ctx.o ct_vfy.o ct_x509v3.o ctype.o curve25519.o cversion.o c_zlib.o d2i_pr.o d2i_pu.o defn_cache.o des_enc.o des_locl.h dh1024.pem dh192.pem dh2048.pem dh4096.pem dh512.pem dh_ameth.o dh_asn1.o dh_check.o dh_depr.o dh_err.o dh_gen.o dh_kdf.o dh_key.o dh_lib.o dh_locl.h dh_meth.o dh_pmeth.o dh_prn.o dh_rfc5114.o dh_rfc7919.o digest.o dllmain.o drbg_ctr.o drbg_hash.o drbg_hmac.o drbg_lib.o dsa_ameth.o dsa_asn1.o dsa_depr.o dsa_err.o dsa_gen.o dsa_key.o dsa_lib.o dsa_locl.h dsa_meth.o dsa_ossl.o dsa_pmeth.o dsa_prn.o dsa_sign.o dsa_vrf.o dso_dl.o dso_dlfcn.o dso_err.o dso_lib.o dso_locl.h dso_openssl.o dso_vms.o dso_win32.o e_aes.o e_aes_cbc_hmac_sha1.o e_aes_cbc_hmac_sha256.o e_aria.o ebcdic.o e_bf.o ec2_oct.o ec2_smpl.o e_camellia.o ec_ameth.o ec_asn1.o e_cast.o ecb3_enc.o ecb_enc.o ec_check.o ec_curve.o ec_cvt.o ecdh_kdf.o ecdh_ossl.o ecdsa_ossl.o ecdsa_sign.o ecdsa_vrf.o ec_err.o e_chacha20_poly1305.o ec_key.o ec_kmeth.o eck_prn.o ec_lcl.h ec_lib.o ec_mult.o ec_oct.o ec_pmeth.o ecp_mont.o ecp_nist.o ecp_nistp224.o ecp_nistp256.o ecp_nistp521.o ecp_nistputil.o ecp_nistz256.o ecp_nistz256_table.o ecp_oct.o ec_print.o ecp_smpl.o ecx_meth.o e_des3.o e_des.o e_idea.o encode.o eng_all.o eng_cnf.o eng_ctrl.o eng_dyn.o eng_err.o eng_fat.o eng_init.o eng_int.h eng_lib.o eng_list.o eng_openssl.o eng_pkey.o eng_rdrand.o eng_table.o e_null.o e_old.o e_rc2.o e_rc4.o e_rc4_hmac_md5.o e_rc5.o err_all.o err.o err_prn.o e_seed.o e_sm4.o ess_asn1.o ess_err.o ess_lib.o evp_asn1.o evp_cnf.o evp_enc.o evp_err.o evp_key.o evp_lib.o evp_locl.h evp_pbe.o evp_pkey.o e_xcbc_d.o ex_data.o ext_dat.h fcrypt_b.o fcrypt.o file f_int.o f_string.o gcm128.o getenv.o gmac.o hkdf.o hmac.o hmac_lcl.h hm_ameth.o hm_meth.o i2d_pr.o i2d_pu.o ia64cpuid.S i_cbc.o i_cfb64.o idea_lcl.h i_ecb.o init.o i_ofb64.o i_skey.o kdf_err.o kdf_lib.o kdf_local.h kdf_util.o keccak1600.o kmac.o lhash.o lhash_lcl.h lh_stats.o loader_file.o LPdir_nyi.o LPdir_unix.o LPdir_vms.o LPdir_win32.o LPdir_win.o LPdir_wince.o mac_lib.o m_blake2b.o m_blake2s.o md2_dgst.o md2_one.o md4_dgst.o md4_locl.h md4_one.o md5_dgst.o md5_locl.h md5_one.o mdc2dgst.o mdc2_one.o mem.o mem_clr.o mem_dbg.o mem_sec.o mips_arch.h m_md2.o m_md4.o m_md5.o m_md5_sha1.o m_mdc2.o m_null.o modes_lcl.h m_ripemd.o m_sha1.o m_sha3.o m_sigver.o m_sm3.o m_wp.o names.o ncbc_enc.o n_pkey.o nsseq.o obj_dat.o obj_dat.h objects.txt obj_err.o obj_lcl.h obj_lib.o obj_mac.num obj_xref.o obj_xref.h obj_xref.txt ocb128.o ocsp_asn.o ocsp_cl.o ocsp_err.o ocsp_ext.o ocsp_ht.o ocsp_lcl.h ocsp_lib.o ocsp_prn.o ocsp_srv.o ocsp_vfy.o o_dir.o ofb128.o ofb64ede.o ofb64enc.o ofb_enc.o o_fips.o o_fopen.o o_init.o o_names.o openssl.ec openssl.txt o_str.o o_time.o p12_add.o p12_asn.o p12_attr.o p12_crpt.o p12_crt.o p12_decr.o p12_init.o p12_key.o p12_kiss.o p12_lcl.h p12_mutl.o p12_npas.o p12_p8d.o p12_p8e.o p12_sbag.o p12_utl.o p5_crpt2.o p5_crpt.o p5_pbe.o p5_pbev2.o p5_scrypt.o p8_pkey.o pbe_scrypt.o pbkdf2.o pcbc_enc.o pcy_cache.o pcy_data.o pcy_int.h pcy_lib.o pcy_map.o pcy_node.o pcy_tree.o p_dec.o pem_all.o pem_err.o pem_info.o pem_lib.o pem_oth.o pem_pk8.o pem_pkey.o pem_sign.o pem_x509.o pem_xaux.o p_enc.o pk12err.o pk7_asn1.o pk7_attr.o pk7_doit.o pk7_lib.o pk7_mime.o pk7_smime.o pkcs7err.o pkey_kdf.o pkey_mac.o p_lib.o pmeth_fn.o pmeth_gn.o pmeth_lib.o poly1305_ameth.o poly1305_base2_44.o poly1305.o poly1305_ieee754.o poly1305_local.h poly1305_meth.o p_open.o ppc_arch.h ppccap.o properties.ebnf properties.xhtml property.o property_err.o property_lcl.h property_parse.o property_string.o p_seal.o p_sign.o p_verify.o pvkfmt.o qud_cksm.o rand_egd.o rand_err.o randfile.o rand_key.o rand_lcl.h rand_lib.o rand_unix.o rand_vms.o rand_win.o rc2_cbc.o rc2cfb64.o rc2_ecb.o rc2_locl.h rc2ofb64.o rc2_skey.o rc4_enc.o rc4_locl.h rc4_skey.o rc5cfb64.o rc5_ecb.o rc5_enc.o rc5_locl.h rc5ofb64.o rc5_skey.o README README.pod README.sparse_array rmdconst.h rmd_dgst.o rmd_locl.h rmd_one.o rsa_ameth.o rsa_asn1.o rsa_chk.o rsa_crpt.o rsa_depr.o rsa_err.o rsa_gen.o rsa_lib.o rsa_locl.h rsa_meth.o rsa_mp.o rsa_none.o rsa_oaep.o rsa_ossl.o rsa_pk1.o rsa_pmeth.o rsa_prn.o rsa_pss.o rsa_saos.o rsa_sign.o rsa_ssl.o rsa_x931.o rsa_x931g.o rsaz_exp.o rsaz_exp.h s390x_arch.h s390xcap.o s390x.pm scrypt.o seed.o seed_cbc.o seed_cfb.o seed_ecb.o seed_locl.h seed_ofb.o set_key.o sha1dgst.o sha1_one.o sha256.o sha512.o sha_locl.h siphash_ameth.o siphash.o siphash_local.h siphash_meth.o siv128.o sm2_crypt.o sm2_err.o sm2_pmeth.o sm2_sign.o sm3.o sm3_locl.h sm4.o sparc_arch.h sparccpuid.S sparcv9cap.o sparse_array.o spr.h srp_lib.o srp_vfy.o sshkdf.o stack.o standard_exts.h standard_methods.h store_err.o store_init.o store_lib.o store_locl.h store_register.o store_strings.o str2key.o tasn_dec.o tasn_enc.o tasn_fre.o tasn_new.o tasn_prn.o tasn_scn.o tasn_typ.o tasn_utl.o tb_asnmth.o tb_cipher.o tb_dh.o tb_digest.o tb_dsa.o tb_eckey.o t_bitst.o tbl_standard.h tb_pkmeth.o tb_rand.o tb_rsa.o t_crl.o threads_none.o threads_pthread.o threads_win.o tls1_prf.o t_pkey.o t_req.o ts_asn1.o ts_conf.o ts_err.o ts_lcl.h ts_lib.o t_spki.o ts_req_print.o ts_req_utils.o ts_rsp_print.o ts_rsp_sign.o ts_rsp_utils.o ts_rsp_verify.o ts_verify_ctx.o t_x509.o txt_db.o uid.o ui_err.o ui_lib.o ui_locl.h ui_null.o ui_openssl.o ui_util.o v3_addr.o v3_admis.o v3_admis.h v3_akeya.o v3_akey.o v3_alt.o v3_asid.o v3_bcons.o v3_bitst.o v3_conf.o v3_cpols.o v3_crld.o v3_enum.o v3err.o v3_extku.o v3_genn.o v3_ia5.o v3_info.o v3_int.o v3_lib.o v3_ncons.o v3_ocsp.o v3_pcia.o v3_pci.o v3_pcons.o v3_pku.o v3_pmaps.o v3_prn.o v3_purp.o v3_skey.o v3_sxnet.o v3_tlsf.o v3_utl.o vms_rms.h wp_block.o wp_dgst.o wp_locl.h wrap128.o x509_att.o x509_cmp.o x509cset.o x509_d2.o x509_def.o x509_err.o x509_ext.o x509_lcl.h x509_lu.o x509_meth.o x509name.o x509_obj.o x509_r2x.o x509_req.o x509rset.o x509_set.o x509spki.o x509_trs.o x509_txt.o x509type.o x509_v3.o x509_vfy.o x509_vpm.o x_algor.o x_all.o x_attrib.o x_bignum.o xcbc_enc.o x_crl.o x_exten.o x_info.o x_int64.o x_long.o x_name.o x_pkey.o x_pubkey.o x_req.o x_sig.o x_spki.o xts128.o x_val.o x_x509a.o x_x509.o
obj-y += mesh.o

# This option is not just y/n - it can have a numeric value
ifdef CONFIG_BOOT_RETRY_TIME
obj-y += bootretry.o
endif

# boards
obj-y += board_f.o
obj-y += board_r.o
obj-$(CONFIG_DISPLAY_BOARDINFO) += board_info.o
obj-$(CONFIG_DISPLAY_BOARDINFO_LATE) += board_info.o

obj-$(CONFIG_CMD_BOOTM) += bootm.o bootm_os.o
obj-$(CONFIG_CMD_BOOTZ) += bootm.o bootm_os.o
obj-$(CONFIG_CMD_BOOTI) += bootm.o bootm_os.o

# environment
obj-y += env_attr.o
obj-y += env_callback.o
obj-y += env_flags.o
obj-$(CONFIG_ENV_IS_IN_DATAFLASH) += env_dataflash.o
obj-$(CONFIG_ENV_IS_IN_EEPROM) += env_eeprom.o
extra-$(CONFIG_ENV_IS_EMBEDDED) += env_embedded.o
obj-$(CONFIG_ENV_IS_IN_EEPROM) += env_embedded.o
extra-$(CONFIG_ENV_IS_IN_FLASH) += env_embedded.o
obj-$(CONFIG_ENV_IS_IN_NVRAM) += env_embedded.o
obj-$(CONFIG_ENV_IS_IN_FLASH) += env_flash.o
obj-$(CONFIG_ENV_IS_IN_MMC) += env_mmc.o
obj-$(CONFIG_ENV_IS_IN_FAT) += env_fat.o
obj-$(CONFIG_ENV_IS_IN_EXT4) += env_ext4.o
obj-$(CONFIG_ENV_IS_IN_NAND) += env_nand.o
obj-$(CONFIG_ENV_IS_IN_NVRAM) += env_nvram.o
obj-$(CONFIG_ENV_IS_IN_ONENAND) += env_onenand.o
obj-$(CONFIG_ENV_IS_IN_SATA) += env_sata.o
obj-$(CONFIG_ENV_IS_IN_SPI_FLASH) += env_sf.o
obj-$(CONFIG_ENV_IS_IN_REMOTE) += env_remote.o
obj-$(CONFIG_ENV_IS_IN_UBI) += env_ubi.o
obj-$(CONFIG_ENV_IS_NOWHERE) += env_nowhere.o

obj-$(CONFIG_CMD_BEDBUG) += bedbug.o
obj-$(CONFIG_$(SPL_)OF_LIBFDT) += fdt_support.o

obj-$(CONFIG_MII) += miiphyutil.o
obj-$(CONFIG_CMD_MII) += miiphyutil.o
obj-$(CONFIG_PHYLIB) += miiphyutil.o

ifdef CONFIG_CMD_USB
obj-y += usb.o usb_hub.o
obj-$(CONFIG_USB_STORAGE) += usb_storage.o
endif

# others
obj-$(CONFIG_BOOTSTAGE) += bootstage.o
obj-$(CONFIG_CONSOLE_MUX) += iomux.o
obj-y += flash.o
obj-$(CONFIG_CMD_KGDB) += kgdb.o kgdb_stubs.o
obj-$(CONFIG_I2C_EDID) += edid.o
obj-$(CONFIG_KALLSYMS) += kallsyms.o
obj-y += splash.o
obj-$(CONFIG_SPLASH_SOURCE) += splash_source.o
ifndef CONFIG_DM_VIDEO
obj-$(CONFIG_LCD) += lcd.o lcd_console.o
endif
obj-$(CONFIG_LCD_ROTATION) += lcd_console_rotation.o
obj-$(CONFIG_LCD_DT_SIMPLEFB) += lcd_simplefb.o
obj-$(CONFIG_LYNXKDI) += lynxkdi.o
obj-$(CONFIG_MENU) += menu.o
obj-$(CONFIG_CMD_SATA) += sata.o
obj-$(CONFIG_SCSI) += scsi.o
obj-$(CONFIG_UPDATE_TFTP) += update.o
obj-$(CONFIG_DFU_TFTP) += update.o
obj-$(CONFIG_USB_KEYBOARD) += usb_kbd.o

endif # !CONFIG_SPL_BUILD

ifdef CONFIG_SPL_BUILD
obj-$(CONFIG_SPL_DFU_SUPPORT) += dfu.o
obj-$(CONFIG_SPL_DFU_SUPPORT) += cli_hush.o
obj-$(CONFIG_SPL_HASH_SUPPORT) += hash.o
obj-$(CONFIG_ENV_IS_IN_FLASH) += env_flash.o
obj-$(CONFIG_SPL_YMODEM_SUPPORT) += xyzModem.o
obj-$(CONFIG_SPL_NET_SUPPORT) += miiphyutil.o
obj-$(CONFIG_SPL_OF_TRANSLATE) += fdt_support.o
ifdef CONFIG_SPL_USB_HOST_SUPPORT
obj-$(CONFIG_SPL_USB_SUPPORT) += usb.o usb_hub.o
obj-$(CONFIG_USB_STORAGE) += usb_storage.o
endif
# environment
ifdef CONFIG_TPL_BUILD
obj-$(CONFIG_TPL_ENV_SUPPORT) += env_attr.o
obj-$(CONFIG_TPL_ENV_SUPPORT) += env_flags.o
obj-$(CONFIG_TPL_ENV_SUPPORT) += env_callback.o
else
obj-$(CONFIG_SPL_ENV_SUPPORT) += env_attr.o
obj-$(CONFIG_SPL_ENV_SUPPORT) += env_flags.o
obj-$(CONFIG_SPL_ENV_SUPPORT) += env_callback.o
endif
ifneq ($(CONFIG_TPL_ENV_SUPPORT)$(CONFIG_SPL_ENV_SUPPORT),)
obj-$(CONFIG_ENV_IS_NOWHERE) += env_nowhere.o
obj-$(CONFIG_ENV_IS_IN_MMC) += env_mmc.o
obj-$(CONFIG_ENV_IS_IN_FAT) += env_fat.o
obj-$(CONFIG_ENV_IS_IN_EXT4) += env_ext4.o
obj-$(CONFIG_ENV_IS_IN_NAND) += env_nand.o
obj-$(CONFIG_ENV_IS_IN_SPI_FLASH) += env_sf.o
obj-$(CONFIG_ENV_IS_IN_FLASH) += env_flash.o
endif
ifdef CONFIG_SPL_SATA_SUPPORT
obj-$(CONFIG_SCSI) += scsi.o
endif
endif
#environment
obj-y += env_common.o
#others
obj-$(CONFIG_DDR_SPD) += ddr_spd.o
obj-$(CONFIG_SPD_EEPROM) += ddr_spd.o
obj-$(CONFIG_HWCONFIG) += hwconfig.o
obj-$(CONFIG_BOUNCE_BUFFER) += bouncebuf.o
ifdef CONFIG_SPL_BUILD
ifdef CONFIG_TPL_BUILD
obj-$(CONFIG_TPL_SERIAL_SUPPORT) += console.o
else
obj-$(CONFIG_SPL_SERIAL_SUPPORT) += console.o
endif
else
obj-y += console.o
endif
obj-$(CONFIG_CROS_EC) += cros_ec.o
obj-y += dlmalloc.o
ifdef CONFIG_SYS_MALLOC_F_LEN
obj-y += malloc_simple.o
endif
obj-$(CONFIG_CMD_IDE) += ide.o
obj-y += image.o
obj-$(CONFIG_ANDROID_BOOT_IMAGE) += image-android.o
obj-$(CONFIG_$(SPL_)OF_LIBFDT) += image-fdt.o
obj-$(CONFIG_$(SPL_)FIT) += image-fit.o
obj-$(CONFIG_$(SPL_)FIT_SIGNATURE) += image-sig.o
obj-$(CONFIG_IO_TRACE) += iotrace.o
obj-y += memsize.o
obj-y += stdio.o

# This option is not just y/n - it can have a numeric value
ifdef CONFIG_FASTBOOT_FLASH
obj-y += image-sparse.o
ifdef CONFIG_FASTBOOT_FLASH_MMC_DEV
obj-y += fb_mmc.o
endif
ifdef CONFIG_FASTBOOT_FLASH_NAND_DEV
obj-y += fb_nand.o
endif
endif

ifdef CONFIG_CMD_EEPROM_LAYOUT
obj-y += eeprom/eeprom_field.o eeprom/eeprom_layout.o
endif
# We always have this since drivers/ddr/fs/interactive.o needs it
obj-$(CONFIG_CMDLINE) += cli_simple.o

obj-y += cli.o
obj-$(CONFIG_CMDLINE) += cli_readline.o
obj-$(CONFIG_CMD_DFU) += dfu.o
obj-y += command.o
obj-y += s_record.o
obj-y += xyzModem.o

CFLAGS_env_embedded.o := -Wa,--no-warn -DENV_CRC=$(shell tools/envcrc 2>/dev/null)
