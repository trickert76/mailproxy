#!/bin/bash

##########################################################################
# >> DEFAULT VARS
#
# add them here.
# Example: DEFAULT_VARS["KEY"]="VALUE"
##########################################################################
declare -A DEFAULT_VARS
DEFAULT_VARS["ENABLE_POP3"]="${ENABLE_POP3:="1"}"
DEFAULT_VARS["ENABLE_FAIL2BAN"]="${ENABLE_FAIL2BAN:="0"}"
DEFAULT_VARS["ENABLE_MANAGESIEVE"]="${ENABLE_MANAGESIEVE:="0"}"
DEFAULT_VARS["LDAP_START_TLS"]="${LDAP_START_TLS:="no"}"
DEFAULT_VARS["DOVECOT_TLS"]="${DOVECOT_TLS:="no"}"
DEFAULT_VARS["DOVECOT_MAILBOX_FORMAT"]="${DOVECOT_MAILBOX_FORMAT:="maildir"}"
DEFAULT_VARS["POSTSCREEN_ACTION"]="${POSTSCREEN_ACTION:="enforce"}"
DEFAULT_VARS["SPOOF_PROTECTION"]="${SPOOF_PROTECTION:="0"}"
DEFAULT_VARS["TLS_LEVEL"]="${TLS_LEVEL:="modern"}"

##########################################################################
# << DEFAULT VARS
##########################################################################

##########################################################################
# >> GLOBAL VARS
#
# add your global script variables here.
#
# Example: KEY="VALUE"
##########################################################################
HOSTNAME="$(hostname -f)"
DOMAINNAME="$(hostname -d)"
CHKSUM_FILE=/tmp/docker-mailserver-config-chksum
##########################################################################
# << GLOBAL VARS
##########################################################################


##########################################################################
# >> REGISTER FUNCTIONS
#
# add your new functions/methods here.
#
# NOTE: position matters when registering a function in stacks. First in First out
# 		Execution Logic:
# 			> check functions
# 			> setup functions
# 			> fix functions
# 			> misc functions
# 			> start-daemons
#
# Example:
# if [ CONDITION IS MET ]; then
#   _register_{setup,fix,check,start}_{functions,daemons} "$FUNCNAME"
# fi
#
# Implement them in the section-group: {check,setup,fix,start}
##########################################################################
function register_functions() {
	notify 'taskgrp' 'Initializing setup'
	notify 'task' 'Registering check,setup,fix,misc and start-daemons functions'

	################### >> check funcs

	_register_check_function "_check_environment_variables"
	_register_check_function "_check_hostname"

	################### << check funcs

	################### >> setup funcs

	_register_setup_function "_setup_default_vars"
	_register_setup_function "_setup_file_permissions"

	_register_setup_function "_setup_dovecot"
	_register_setup_function "_setup_dovecot_dhparam"
	_register_setup_function "_setup_dovecot_quota"
	_register_setup_function "_setup_dovecot_local_user"

	_register_setup_function "_setup_dkim"
	_register_setup_function "_setup_ssl"

	_register_setup_function "_setup_docker_permit"

	_register_setup_function "_setup_mailname"
	_register_setup_function "_setup_dmarc_hostname"
	_register_setup_function "_setup_dovecot_hostname"

	if [ "$SPOOF_PROTECTION" = 1  ]; then
		_register_setup_function "_setup_spoof_protection"
	fi

	_register_setup_function "_setup_environment"
	_register_setup_function "_setup_logrotate"

	if [ "$LOGWATCH_TRIGGER" != "none" ]; then
		_register_setup_function "_setup_logwatch"
	fi

	_register_setup_function "_setup_user_patches"

        # Compute last as the config files are modified in-place
        _register_setup_function "_setup_chksum_file"

	################### << setup funcs

	################### >> fix funcs

	_register_fix_function "_fix_var_mail_permissions"

	################### << fix funcs

	################### >> misc funcs

	_register_misc_function "_misc_save_states"

	################### << misc funcs

	################### >> daemon funcs

	_register_start_daemon "_start_daemons_cron"
	_register_start_daemon "_start_daemons_rsyslog"

	_register_start_daemon "_start_daemons_dovecot"

	# needs to be started before saslauthd
	_register_start_daemon "_start_daemons_opendkim"
	_register_start_daemon "_start_daemons_opendmarc"

	if [ "$ENABLE_FAIL2BAN" = 1 ]; then
		_register_start_daemon "_start_daemons_fail2ban"
	fi

	################### << daemon funcs
}
##########################################################################
# << REGISTER FUNCTIONS
##########################################################################



# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !  CARE --> DON'T CHANGE, unless you exactly know what you are doing
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# >>


##########################################################################
# >> CONSTANTS
##########################################################################
declare -a FUNCS_SETUP
declare -a FUNCS_FIX
declare -a FUNCS_CHECK
declare -a FUNCS_MISC
declare -a DAEMONS_START
declare -A HELPERS_EXEC_STATE
##########################################################################
# << CONSTANTS
##########################################################################


##########################################################################
# >> protected register_functions
##########################################################################
function _register_start_daemon() {
	DAEMONS_START+=($1)
	notify 'inf' "$1() registered"
}

function _register_setup_function() {
	FUNCS_SETUP+=($1)
	notify 'inf' "$1() registered"
}

function _register_fix_function() {
	FUNCS_FIX+=($1)
	notify 'inf' "$1() registered"
}

function _register_check_function() {
	FUNCS_CHECK+=($1)
	notify 'inf' "$1() registered"
}

function _register_misc_function() {
	FUNCS_MISC+=($1)
	notify 'inf' "$1() registered"
}
##########################################################################
# << protected register_functions
##########################################################################


function notify () {
	c_red="\e[0;31m"
	c_green="\e[0;32m"
	c_brown="\e[0;33m"
	c_blue="\e[0;34m"
	c_bold="\033[1m"
	c_reset="\e[0m"

	notification_type=$1
	notification_msg=$2
	notification_format=$3
	msg=""

	case "${notification_type}" in
		'taskgrp')
			msg="${c_bold}${notification_msg}${c_reset}"
			;;
		'task')
			if [[ ${DEFAULT_VARS["DMS_DEBUG"]} == 1 ]]; then
				msg="  ${notification_msg}${c_reset}"
			fi
			;;
		'inf')
			if [[ ${DEFAULT_VARS["DMS_DEBUG"]} == 1 ]]; then
				msg="${c_green}  * ${notification_msg}${c_reset}"
			fi
			;;
		'started')
			msg="${c_green} ${notification_msg}${c_reset}"
			;;
		'warn')
			msg="${c_brown}  * ${notification_msg}${c_reset}"
			;;
		'err')
			msg="${c_red}  * ${notification_msg}${c_reset}"
			;;
		'fatal')
			msg="${c_red}Error: ${notification_msg}${c_reset}"
			;;
		*)
			msg=""
			;;
	esac

	case "${notification_format}" in
		'n')
			options="-ne"
	  	;;
		*)
  		options="-e"
			;;
	esac

	[[ ! -z "${msg}" ]] && echo $options "${msg}"
}

function defunc() {
	notify 'fatal' "Please fix your configuration. Exiting..."
	exit 1
}

function display_startup_daemon() {
  $1 &>/dev/null
  res=$?
  if [[ ${DEFAULT_VARS["DMS_DEBUG"]} == 1 ]]; then
	  if [ $res = 0 ]; then
			notify 'started' " [ OK ]"
		else
	  	echo "false"
			notify 'err' " [ FAILED ]"
		fi
  fi
	return $res
}

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !  CARE --> DON'T CHANGE, except you know exactly what you are doing
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# <<



##########################################################################
# >> Check Stack
#
# Description: Place functions for initial check of container sanity
##########################################################################
function check() {
	notify 'taskgrp' 'Checking configuration'
	for _func in "${FUNCS_CHECK[@]}";do
		$_func
		[ $? != 0 ] && defunc
	done
}

function _check_hostname() {
	notify "task" "Check that hostname/domainname is provided or overidden (no default docker hostname/kubernetes) [$FUNCNAME]"

	if [[ ! -z ${DEFAULT_VARS["OVERRIDE_HOSTNAME"]} ]]; then
		export HOSTNAME=${DEFAULT_VARS["OVERRIDE_HOSTNAME"]}
		export DOMAINNAME=$(echo $HOSTNAME | sed s/[^.]*.//)
	fi

	notify 'inf' "Domain has been set to $DOMAINNAME"
	notify 'inf' "Hostname has been set to $HOSTNAME"

	if ( ! echo $HOSTNAME | grep -E '^(\S+[.]\S+)$' > /dev/null ); then
		notify 'err' "Setting hostname/domainname is required"
		kill `cat /var/run/supervisord.pid` && return 1
	else
		return 0
	fi
}

function _check_environment_variables() {
	notify "task" "Check that there are no conflicts with env variables [$FUNCNAME]"
	return 0
}
##########################################################################
# << Check Stack
##########################################################################


##########################################################################
# >> Setup Stack
#
# Description: Place functions for functional configurations here
##########################################################################
function setup() {
	notify 'taskgrp' 'Configuring mail server'
	for _func in "${FUNCS_SETUP[@]}";do
		$_func
	done
}

function _setup_default_vars() {
	notify 'task' "Setting up default variables [$FUNCNAME]"

	# update POSTMASTER_ADDRESS - must be done done after _check_hostname()
	DEFAULT_VARS["POSTMASTER_ADDRESS"]="${POSTMASTER_ADDRESS:=postmaster@${DOMAINNAME}}"

	# update REPORT_SENDER - must be done done after _check_hostname()
	DEFAULT_VARS["REPORT_SENDER"]="${REPORT_SENDER:=mailserver-report@${HOSTNAME}}"
	DEFAULT_VARS["PFLOGSUMM_SENDER"]="${PFLOGSUMM_SENDER:=${REPORT_SENDER}}"

	# set PFLOGSUMM_TRIGGER here for backwards compatibility
	# when REPORT_RECIPIENT is on the old method should be used
	if [ "$REPORT_RECIPIENT" == "0" ]; then
		DEFAULT_VARS["PFLOGSUMM_TRIGGER"]="${PFLOGSUMM_TRIGGER:="none"}"
	else
		DEFAULT_VARS["PFLOGSUMM_TRIGGER"]="${PFLOGSUMM_TRIGGER:="logrotate"}"
	fi

	# Expand address to simplify the rest of the script
	if [ "$REPORT_RECIPIENT" == "0" ] || [ "$REPORT_RECIPIENT" == "1" ]; then
		REPORT_RECIPIENT="$POSTMASTER_ADDRESS"
		DEFAULT_VARS["REPORT_RECIPIENT"]="${REPORT_RECIPIENT}"
	fi
	DEFAULT_VARS["PFLOGSUMM_RECIPIENT"]="${PFLOGSUMM_RECIPIENT:=${REPORT_RECIPIENT}}"
	DEFAULT_VARS["LOGWATCH_RECIPIENT"]="${LOGWATCH_RECIPIENT:=${REPORT_RECIPIENT}}"

	for var in ${!DEFAULT_VARS[@]}; do
		echo "export $var=\"${DEFAULT_VARS[$var]}\"" >> /root/.bashrc
		[ $? != 0 ] && notify 'err' "Unable to set $var=${DEFAULT_VARS[$var]}" && kill -15 `cat /var/run/supervisord.pid` && return 1
		notify 'inf' "Set $var=${DEFAULT_VARS[$var]}"
	done
}

# File/folder permissions are fine when using docker volumes, but may be wrong
# when file system folders are mounted into the container.
# Set the expected values and create missing folders/files just in case.
function _setup_file_permissions() {
	notify 'task' "Setting file/folder permissions"

	mkdir -p /var/log/supervisor

	mkdir -p /var/log/mail
	chown syslog:root /var/log/mail

	touch /var/log/mail/clamav.log
	chown clamav:adm /var/log/mail/clamav.log
	chmod 640 /var/log/mail/clamav.log

	touch /var/log/mail/freshclam.log
	chown clamav:adm /var/log/mail/freshclam.log
	chmod 640 /var/log/mail/freshclam.log
}

function _setup_chksum_file() {
        notify 'task' "Setting up configuration checksum file"


        if [ -d /tmp/docker-mailserver ]; then
          pushd /tmp/docker-mailserver

          declare -a cf_files=()
          for file in dovecot-quotas.cf; do
            [ -f "$file" ] && cf_files+=("$file")
          done

          notify 'inf' "Creating $CHKSUM_FILE"
          sha512sum ${cf_files[@]/#/--tag } >$CHKSUM_FILE

          popd
        else
          # We could just skip the file, but perhaps config can be added later?
          # If so it must be processed by the check for changes script
          notify 'inf' "Creating empty $CHKSUM_FILE (no config)"
          touch $CHKSUM_FILE
        fi
}

function _setup_mailname() {
	notify 'task' 'Setting up Mailname'

	notify 'inf' "Creating /etc/mailname"
	echo $DOMAINNAME > /etc/mailname
}


function _setup_dmarc_hostname() {
	notify 'task' 'Setting up dmarc'

	notify 'inf' "Applying hostname to /etc/opendmarc.conf"
	sed -i -e 's/^AuthservID.*$/AuthservID          '$HOSTNAME'/g' \
	       -e 's/^TrustedAuthservIDs.*$/TrustedAuthservIDs  '$HOSTNAME'/g' /etc/opendmarc.conf
}

function _setup_dovecot_hostname() {
	notify 'task' 'Applying hostname to Dovecot'

	notify 'inf' "Applying hostname to /etc/dovecot/conf.d/15-lda.conf"
	sed -i 's/^#hostname =.*$/hostname = '$HOSTNAME'/g' /etc/dovecot/conf.d/15-lda.conf
}

function _setup_dovecot() {
	notify 'task' 'Setting up Dovecot'

        # Moved from docker file, copy or generate default self-signed cert
        if [ -f /var/mail-state/lib-dovecot/dovecot.pem -a "$ONE_DIR" = 1 ]; then
                notify 'inf' "Copying default dovecot cert"
                cp /var/mail-state/lib-dovecot/dovecot.key /etc/dovecot/ssl/
                cp /var/mail-state/lib-dovecot/dovecot.pem /etc/dovecot/ssl/
        fi
        if [ ! -f /etc/dovecot/ssl/dovecot.pem ]; then
                notify 'inf' "Generating default dovecot cert"
                pushd /usr/share/dovecot
                ./mkcert.sh
                popd

                if [ "$ONE_DIR" = 1 ];then
                        mkdir -p /var/mail-state/lib-dovecot
                        cp /etc/dovecot/ssl/dovecot.key /var/mail-state/lib-dovecot/
                        cp /etc/dovecot/ssl/dovecot.pem /var/mail-state/lib-dovecot/
                fi
        fi

	cp -a /usr/share/dovecot/protocols.d /etc/dovecot/
	# Disable pop3 (it will be eventually enabled later in the script, if requested)
	mv /etc/dovecot/protocols.d/pop3d.protocol /etc/dovecot/protocols.d/pop3d.protocol.disab
	mv /etc/dovecot/protocols.d/managesieved.protocol /etc/dovecot/protocols.d/managesieved.protocol.disab
	sed -i -e 's/#ssl = yes/ssl = yes/g' /etc/dovecot/conf.d/10-master.conf
	sed -i -e 's/#port = 993/port = 993/g' /etc/dovecot/conf.d/10-master.conf
	sed -i -e 's/#port = 995/port = 995/g' /etc/dovecot/conf.d/10-master.conf
	sed -i -e 's/#ssl = yes/ssl = required/g' /etc/dovecot/conf.d/10-ssl.conf
	sed -i 's/^postmaster_address = .*$/postmaster_address = '$POSTMASTER_ADDRESS'/g' /etc/dovecot/conf.d/15-lda.conf

	# Set mail_location according to mailbox format
	case "$DOVECOT_MAILBOX_FORMAT" in
		sdbox|mdbox|maildir )
			notify 'inf' "Dovecot $DOVECOT_MAILBOX_FORMAT format configured"
			sed -i -e 's/^mail_location = .*$/mail_location = '$DOVECOT_MAILBOX_FORMAT':\/var\/mail\/%d\/%n/g' /etc/dovecot/conf.d/10-mail.conf
			;;
		* )
			notify 'inf' "Dovecot maildir format configured (default)"
			sed -i -e 's/^mail_location = .*$/mail_location = maildir:\/var\/mail\/%d\/%n/g' /etc/dovecot/conf.d/10-mail.conf
			;;
	esac

	# Enable Managesieve service by setting the symlink
	# to the configuration file Dovecot will actually find
	if [ "$ENABLE_MANAGESIEVE" = 1 ]; then
		notify 'inf' "Sieve management enabled"
		mv /etc/dovecot/protocols.d/managesieved.protocol.disab /etc/dovecot/protocols.d/managesieved.protocol
	fi

	# Copy pipe and filter programs, if any
	rm -f /usr/lib/dovecot/sieve-filter/*
	rm -f /usr/lib/dovecot/sieve-pipe/*
	[ -d /tmp/docker-mailserver/sieve-filter ] && cp /tmp/docker-mailserver/sieve-filter/* /usr/lib/dovecot/sieve-filter/
	[ -d /tmp/docker-mailserver/sieve-pipe ] && cp /tmp/docker-mailserver/sieve-pipe/* /usr/lib/dovecot/sieve-pipe/

	# create global sieve directories
	mkdir -p /usr/lib/dovecot/sieve-global/before
	mkdir -p /usr/lib/dovecot/sieve-global/after

	if [ -f /tmp/docker-mailserver/before.dovecot.sieve ]; then
		cp /tmp/docker-mailserver/before.dovecot.sieve /usr/lib/dovecot/sieve-global/before/50-before.dovecot.sieve
		sievec /usr/lib/dovecot/sieve-global/before/50-before.dovecot.sieve
	else
	  rm -f /usr/lib/dovecot/sieve-global/before/50-before.dovecot.sieve /usr/lib/dovecot/sieve-global/before/50-before.dovecot.svbin
	fi

	if [ -f /tmp/docker-mailserver/after.dovecot.sieve ]; then
		cp /tmp/docker-mailserver/after.dovecot.sieve /usr/lib/dovecot/sieve-global/after/50-after.dovecot.sieve
		sievec /usr/lib/dovecot/sieve-global/after/50-after.dovecot.sieve
	else
	  rm -f /usr/lib/dovecot/sieve-global/after/50-after.dovecot.sieve /usr/lib/dovecot/sieve-global/after/50-after.dovecot.svbin
	fi

	# sieve will move spams to .Junk folder when SPAMASSASSIN_SPAM_TO_INBOX=1 and MOVE_SPAM_TO_JUNK=1
	if [ "$SPAMASSASSIN_SPAM_TO_INBOX" = 1 ] && [ "$MOVE_SPAM_TO_JUNK" = 1 ]; then
	  notify 'inf' "Spam messages will be moved to the Junk folder."
	  cp /etc/dovecot/sieve/before/60-spam.sieve /usr/lib/dovecot/sieve-global/before/
	  sievec /usr/lib/dovecot/sieve-global/before/60-spam.sieve
	else
	  rm -f /usr/lib/dovecot/sieve-global/before/60-spam.sieve /usr/lib/dovecot/sieve-global/before/60-spam.svbin
	fi

	chown docker:docker -R /usr/lib/dovecot/sieve*
	chmod 550 -R /usr/lib/dovecot/sieve*
	chmod -f +x /usr/lib/dovecot/sieve-pipe/*
}

function _setup_dovecot_quota() {
    notify 'task' 'Setting up Dovecot quota'

    if [ "$ENABLE_LDAP" = 1 ] || [ "$SMTP_ONLY" = 1 ] || [ "$ENABLE_QUOTAS" = 0 ]; then
      # Dovecot quota is disabled when using LDAP or SMTP_ONLY or when explicitly disabled

      # disable dovecot quota in docevot confs
      if [ -f /etc/dovecot/conf.d/90-quota.conf ]; then
        mv /etc/dovecot/conf.d/90-quota.conf /etc/dovecot/conf.d/90-quota.conf.disab
        sed -i "s/mail_plugins = \$mail_plugins quota/mail_plugins = \$mail_plugins/g" /etc/dovecot/conf.d/10-mail.conf
        sed -i "s/mail_plugins = \$mail_plugins imap_quota/mail_plugins = \$mail_plugins/g" /etc/dovecot/conf.d/20-imap.conf
      fi
    else
      if [ -f /etc/dovecot/conf.d/90-quota.conf.disab ]; then
        mv /etc/dovecot/conf.d/90-quota.conf.disab /etc/dovecot/conf.d/90-quota.conf
        sed -i "s/mail_plugins = \$mail_plugins/mail_plugins = \$mail_plugins quota/g" /etc/dovecot/conf.d/10-mail.conf
        sed -i "s/mail_plugins = \$mail_plugin/mail_plugins = \$mail_plugins imap_quota/g" /etc/dovecot/conf.d/20-imap.conf
      fi

      message_size_limit_mb=$((DEFAULT_VARS["POSTFIX_MESSAGE_SIZE_LIMIT"] / 1000000))
      mailbox_limit_mb=$((DEFAULT_VARS["POSTFIX_MAILBOX_SIZE_LIMIT"] / 1000000))

      sed -i "s/quota_max_mail_size =.*/quota_max_mail_size = ${message_size_limit_mb}$([ "$message_size_limit_mb" == 0 ] && echo "" || echo "M")/g" /etc/dovecot/conf.d/90-quota.conf
      sed -i "s/quota_rule = \*:storage=.*/quota_rule = *:storage=${mailbox_limit_mb}$([ "$mailbox_limit_mb" == 0 ] && echo "" || echo "M")/g" /etc/dovecot/conf.d/90-quota.conf

      if [ ! -f /tmp/docker-mailserver/dovecot-quotas.cf ]; then
        notify 'inf' "'config/docker-mailserver/dovecot-quotas.cf' is not provided. Using default quotas."
		    echo -n >/tmp/docker-mailserver/dovecot-quotas.cf
      fi
    fi
}

function _setup_dovecot_local_user() {
	notify 'task' 'Setting up Dovecot Local User'
	echo -n > /etc/postfix/vmailbox
	echo -n > /etc/dovecot/userdb
	if [ -f /tmp/docker-mailserver/postfix-accounts.cf -a "$ENABLE_LDAP" != 1 ]; then
		notify 'inf' "Checking file line endings"
		sed -i 's/\r//g' /tmp/docker-mailserver/postfix-accounts.cf
		notify 'inf' "Regenerating postfix user list"
		echo "# WARNING: this file is auto-generated. Modify config/postfix-accounts.cf to edit user list." > /etc/postfix/vmailbox

		# Checking that /tmp/docker-mailserver/postfix-accounts.cf ends with a newline
		sed -i -e '$a\' /tmp/docker-mailserver/postfix-accounts.cf

		chown dovecot:dovecot /etc/dovecot/userdb
		chmod 640 /etc/dovecot/userdb

		sed -i -e '/\!include auth-ldap\.conf\.ext/s/^/#/' /etc/dovecot/conf.d/10-auth.conf
		sed -i -e '/\!include auth-passwdfile\.inc/s/^#//' /etc/dovecot/conf.d/10-auth.conf

	else
		notify 'inf' "'config/docker-mailserver/postfix-accounts.cf' is not provided. No mail account created."
	fi
}

function _setup_spoof_protection () {
	notify 'inf' "Configuring Spoof Protection"
}

function _setup_dkim() {
	notify 'task' 'Setting up DKIM'

	mkdir -p /etc/opendkim && touch /etc/opendkim/SigningTable

	# Check if keys are already available
	if [ -e "/tmp/docker-mailserver/opendkim/KeyTable" ]; then
		cp -a /tmp/docker-mailserver/opendkim/* /etc/opendkim/
		notify 'inf' "DKIM keys added for: `ls -C /etc/opendkim/keys/`"
		notify 'inf' "Changing permissions on /etc/opendkim"
		chown -R opendkim:opendkim /etc/opendkim/
		# And make sure permissions are right
		chmod -R 0700 /etc/opendkim/keys/
	else
		notify 'warn' "No DKIM key provided. Check the documentation to find how to get your keys."

		local _f_keytable="/etc/opendkim/KeyTable"
		[ ! -f "$_f_keytable" ] && touch "$_f_keytable"
	fi

	# Setup nameservers paramater from /etc/resolv.conf if not defined
	if ! grep '^Nameservers' /etc/opendkim.conf; then
		echo "Nameservers $(grep '^nameserver' /etc/resolv.conf | awk -F " " '{print $2}' | paste -sd ',' -)" >> /etc/opendkim.conf
		notify 'inf' "Nameservers added to /etc/opendkim.conf"
	fi
}

function _setup_ssl() {
	notify 'task' 'Setting up SSL'

  # TLS strength/level configuration
  case $TLS_LEVEL in
    "modern" )
      # Dovecot configuration (secure by default though)
      sed -i -r 's/^ssl_min_protocol =.*$/ssl_min_protocol = TLSv1.2/' /etc/dovecot/conf.d/10-ssl.conf
      sed -i -r 's/^ssl_cipher_list =.*$/ssl_cipher_list = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256/' /etc/dovecot/conf.d/10-ssl.conf

      notify 'inf' "TLS configured with 'modern' ciphers"
    ;;
    "intermediate" )
      # Dovecot configuration
      sed -i -r 's/^ssl_min_protocol = .*$/ssl_min_protocol = TLSv1/' /etc/dovecot/conf.d/10-ssl.conf
      sed -i -r 's/^ssl_cipher_list = .*$/ssl_cipher_list = ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS/' /etc/dovecot/conf.d/10-ssl.conf

      notify 'inf' "TLS configured with 'intermediate' ciphers"
    ;;
  esac

	# SSL certificate Configuration
	case $SSL_TYPE in
		"letsencrypt" )
			# letsencrypt folders and files mounted in /etc/letsencrypt
			if [ -e "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
				KEY=""
				if [ -e "/etc/letsencrypt/live/$HOSTNAME/privkey.pem" ]; then
					KEY="privkey"
				elif [ -e "/etc/letsencrypt/live/$HOSTNAME/key.pem" ]; then
					KEY="key"
				else
					notify 'err' "Cannot access '/etc/letsencrypt/live/"$HOSTNAME"/privkey.pem' nor 'key.pem'"
				fi
				if [ -n "$KEY" ]; then
					notify 'inf' "Adding $HOSTNAME SSL certificate"

					# Dovecot configuration
					sed -i -e 's~ssl_cert = </etc/dovecot/ssl/dovecot\.pem~ssl_cert = </etc/letsencrypt/live/'$HOSTNAME'/fullchain\.pem~g' /etc/dovecot/conf.d/10-ssl.conf
					sed -i -e 's~ssl_key = </etc/dovecot/ssl/dovecot\.key~ssl_key = </etc/letsencrypt/live/'$HOSTNAME'/'"$KEY"'\.pem~g' /etc/dovecot/conf.d/10-ssl.conf

					notify 'inf' "SSL configured with 'letsencrypt' certificates"
				else
					notify 'err' "Key filename not set!"
				fi
			else
				notify 'err' "Cannot access '/etc/letsencrypt/live/"$HOSTNAME"/fullchain.pem'"
			fi
		;;
	"custom" )
		# Adding CA signed SSL certificate if provided in 'postfix/ssl' folder
		if [ -e "/tmp/docker-mailserver/ssl/$HOSTNAME-full.pem" ]; then
			notify 'inf' "Adding $HOSTNAME SSL certificate"
			mkdir -p /etc/postfix/ssl
			cp "/tmp/docker-mailserver/ssl/$HOSTNAME-full.pem" /etc/postfix/ssl

			# Dovecot configuration
			sed -i -e 's~ssl_cert = </etc/dovecot/ssl/dovecot\.pem~ssl_cert = </etc/postfix/ssl/'$HOSTNAME'-full\.pem~g' /etc/dovecot/conf.d/10-ssl.conf
			sed -i -e 's~ssl_key = </etc/dovecot/ssl/dovecot\.key~ssl_key = </etc/postfix/ssl/'$HOSTNAME'-full\.pem~g' /etc/dovecot/conf.d/10-ssl.conf

			notify 'inf' "SSL configured with 'CA signed/custom' certificates"
		fi
		;;
	"manual" )
		# Lets you manually specify the location of the SSL Certs to use. This gives you some more control over this whole processes (like using kube-lego to generate certs)
		if [ -n "$SSL_CERT_PATH" ] \
		&& [ -n "$SSL_KEY_PATH" ]; then
			notify 'inf' "Configuring certificates using cert $SSL_CERT_PATH and key $SSL_KEY_PATH"
			mkdir -p /etc/postfix/ssl
			cp "$SSL_CERT_PATH" /etc/postfix/ssl/cert
			cp "$SSL_KEY_PATH" /etc/postfix/ssl/key
			chmod 600 /etc/postfix/ssl/cert
			chmod 600 /etc/postfix/ssl/key

			# Dovecot configuration
			sed -i -e 's~ssl_cert = </etc/dovecot/ssl/dovecot\.pem~ssl_cert = </etc/postfix/ssl/cert~g' /etc/dovecot/conf.d/10-ssl.conf
			sed -i -e 's~ssl_key = </etc/dovecot/ssl/dovecot\.key~ssl_key = </etc/postfix/ssl/key~g' /etc/dovecot/conf.d/10-ssl.conf

			notify 'inf' "SSL configured with 'Manual' certificates"
		fi
	;;
"self-signed" )
	# Adding self-signed SSL certificate if provided in 'postfix/ssl' folder
	if [ -e "/tmp/docker-mailserver/ssl/$HOSTNAME-cert.pem" ] \
	&& [ -e "/tmp/docker-mailserver/ssl/$HOSTNAME-key.pem"  ] \
	&& [ -e "/tmp/docker-mailserver/ssl/$HOSTNAME-combined.pem" ] \
	&& [ -e "/tmp/docker-mailserver/ssl/demoCA/cacert.pem" ]; then
		notify 'inf' "Adding $HOSTNAME SSL certificate"
		mkdir -p /etc/postfix/ssl
		cp "/tmp/docker-mailserver/ssl/$HOSTNAME-cert.pem" /etc/postfix/ssl
		cp "/tmp/docker-mailserver/ssl/$HOSTNAME-key.pem" /etc/postfix/ssl
		# Force permission on key file
		chmod 600 /etc/postfix/ssl/$HOSTNAME-key.pem
		cp "/tmp/docker-mailserver/ssl/$HOSTNAME-combined.pem" /etc/postfix/ssl
		cp /tmp/docker-mailserver/ssl/demoCA/cacert.pem /etc/postfix/ssl

		ln -s /etc/postfix/ssl/cacert.pem "/etc/ssl/certs/cacert-$HOSTNAME.pem"

		# Dovecot configuration
		sed -i -e 's~ssl_cert = </etc/dovecot/ssl/dovecot\.pem~ssl_cert = </etc/postfix/ssl/'$HOSTNAME'-combined\.pem~g' /etc/dovecot/conf.d/10-ssl.conf
		sed -i -e 's~ssl_key = </etc/dovecot/ssl/dovecot\.key~ssl_key = </etc/postfix/ssl/'$HOSTNAME'-key\.pem~g' /etc/dovecot/conf.d/10-ssl.conf

		notify 'inf' "SSL configured with 'self-signed' certificates"
	fi
	;;
    '' )
        # $SSL_TYPE=empty, no SSL certificate, plain text access

        # Dovecot configuration
        sed -i -e 's~#disable_plaintext_auth = yes~disable_plaintext_auth = no~g' /etc/dovecot/conf.d/10-auth.conf
        sed -i -e 's~ssl = required~ssl = yes~g' /etc/dovecot/conf.d/10-ssl.conf

        notify 'inf' "SSL configured with plain text access"
        ;;
    * )
        # Unknown option, default behavior, no action is required
        notify 'warn' "SSL configured by default"
        ;;
	esac
}

function _setup_docker_permit() {
	notify 'task' 'Setting up PERMIT_DOCKER Option'

	container_ip=$(ip addr show eth0 | grep 'inet ' | sed 's/[^0-9\.\/]*//g' | cut -d '/' -f 1)
	container_network="$(echo $container_ip | cut -d '.' -f1-2).0.0"
	container_networks=$(ip -o -4 addr show type veth | egrep -o '[0-9\.]+/[0-9]+')

	case $PERMIT_DOCKER in
		"host" )
			notify 'inf' "Adding $container_network/16 to my networks"
			postconf -e "$(postconf | grep '^mynetworks =') $container_network/16"
			echo $container_network/16 >> /etc/opendmarc/ignore.hosts
			echo $container_network/16 >> /etc/opendkim/TrustedHosts
			;;

		"network" )
			notify 'inf' "Adding docker network in my networks"
			postconf -e "$(postconf | grep '^mynetworks =') 172.16.0.0/12"
			echo 172.16.0.0/12 >> /etc/opendmarc/ignore.hosts
			echo 172.16.0.0/12 >> /etc/opendkim/TrustedHosts
			;;
		"connected-networks" )
			for network in $container_networks; do
				network=$(_sanitize_ipv4_to_subnet_cidr $network)
				notify 'inf' "Adding docker network $network in my networks"
				postconf -e "$(postconf | grep '^mynetworks =') $network"
				echo $network >> /etc/opendmarc/ignore.hosts
				echo $network >> /etc/opendkim/TrustedHosts
			done
			;;
		* )
			notify 'inf' "Adding container ip in my networks"
			postconf -e "$(postconf | grep '^mynetworks =') $container_ip/32"
			echo $container_ip/32 >> /etc/opendmarc/ignore.hosts
			echo $container_ip/32 >> /etc/opendkim/TrustedHosts
			;;
	esac
}

function _setup_dovecot_dhparam() {
        notify 'task' 'Setting up Dovecot dhparam'
        if [ "$ONE_DIR" = 1 ];then
                DHPARAMS_FILE=/var/mail-state/lib-shared/dhparams.pem
                if [ ! -f $DHPARAMS_FILE ]; then
                        notify 'inf' "Use ffdhe4096 for dhparams (dovecot)"
                        rm -f /etc/dovecot/dh.pem && cp /etc/postfix/shared/ffdhe4096.pem /etc/dovecot/dh.pem
                else
                        notify 'inf' "Use dovecot dhparams that was generated previously"
                        notify 'warn' "Using self-generated dhparams is considered as insecure."
                        notify 'warn' "Unless you known what you are doing, please remove /var/mail-state/lib-shared/dhparams.pem."

                        # Copy from the state directory to the working location
                        rm -f /etc/dovecot/dh.pem && cp $DHPARAMS_FILE /etc/dovecot/dh.pem
                fi
        else
                if [ ! -f /etc/dovecot/dh.pem ]; then
                        if [ -f /etc/postfix/dhparams.pem ]; then
                                notify 'inf' "Copy postfix dhparams to dovecot"
                                cp /etc/postfix/dhparams.pem /etc/dovecot/dh.pem
                        elif [ -f /tmp/docker-mailserver/dhparams.pem ]; then
                                notify 'inf' "Copy pre-generated dhparams to dovecot"
                                notify 'warn' "Using self-generated dhparams is considered as insecure."
                                notify 'warn' "Unless you known what you are doing, please remove /tmp/docker-mailserver/dhparams.pem."
                                cp /tmp/docker-mailserver/dhparams.pem /etc/dovecot/dh.pem
                        else
			                          notify 'inf' "Use ffdhe4096 for dhparams (dovecot)"
                                cp /etc/postfix/shared/ffdhe4096.pem /etc/dovecot/dh.pem
                        fi
                else
                        notify 'inf' "Use existing dovecot dhparams"
                        notify 'warn' "Using self-generated dhparams is considered as insecure."
                        notify 'warn' "Unless you known what you are doing, please remove /etc/dovecot/dh.pem."
                fi
        fi
}

function _setup_security_stack() {
	notify 'task' "Setting up Security Stack"

	# Fail2ban
	if [ "$ENABLE_FAIL2BAN" = 1 ]; then
		notify 'inf' "Fail2ban enabled"
		test -e /tmp/docker-mailserver/fail2ban-fail2ban.cf && cp /tmp/docker-mailserver/fail2ban-fail2ban.cf /etc/fail2ban/fail2ban.local
		test -e /tmp/docker-mailserver/fail2ban-jail.cf && cp /tmp/docker-mailserver/fail2ban-jail.cf /etc/fail2ban/jail.local
	else
		# Disable logrotate config for fail2ban if not enabled
		rm -f /etc/logrotate.d/fail2ban
	fi
}

function _setup_logrotate() {
	notify 'inf' "Setting up logrotate"

	LOGROTATE="/var/log/mail/mail.log\n{\n  compress\n  copytruncate\n  delaycompress\n"
	case "$LOGROTATE_INTERVAL" in
		"daily" )
			notify 'inf' "Setting postfix logrotate interval to daily"
			LOGROTATE="$LOGROTATE  rotate 1\n  daily\n"
			;;
		"weekly" )
			notify 'inf' "Setting postfix logrotate interval to weekly"
			LOGROTATE="$LOGROTATE  rotate 1\n  weekly\n"
			;;
		"monthly" )
			notify 'inf' "Setting postfix logrotate interval to monthly"
			LOGROTATE="$LOGROTATE  rotate 1\n  monthly\n"
			;;
	esac
	LOGROTATE="$LOGROTATE}"
	echo -e "$LOGROTATE" > /etc/logrotate.d/maillog
}

function _setup_mail_summary() {
	notify 'inf' "Enable postfix summary with recipient $PFLOGSUMM_RECIPIENT"
        case "$PFLOGSUMM_TRIGGER" in
                "daily_cron" )
                        notify 'inf' "Creating daily cron job for pflogsumm report"
			echo "#!/bin/bash" > /etc/cron.daily/postfix-summary
			echo "/usr/local/bin/report-pflogsumm-yesterday $HOSTNAME $PFLOGSUMM_RECIPIENT $PFLOGSUMM_SENDER" \
			 >> /etc/cron.daily/postfix-summary
			chmod +x /etc/cron.daily/postfix-summary
                        ;;
                "logrotate" )
                        notify 'inf' "Add postrotate action for pflogsumm report"
			sed -i "s|}|  postrotate\n    /usr/local/bin/postfix-summary $HOSTNAME \
    $PFLOGSUMM_RECIPIENT $PFLOGSUMM_SENDER\n  endscript\n}\n|" /etc/logrotate.d/maillog
                        ;;
        esac
}

function _setup_logwatch() {
	notify 'inf' "Enable logwatch reports with recipient $LOGWATCH_RECIPIENT"
  echo "LogFile = /var/log/mail/freshclam.log" >> /etc/logwatch/conf/logfiles/clam-update.conf
	case "$LOGWATCH_INTERVAL" in
		"daily" )
			notify 'inf' "Creating daily cron job for logwatch reports"
			echo "#!/bin/bash" > /etc/cron.daily/logwatch
			echo "/usr/sbin/logwatch --range Yesterday --hostname $HOSTNAME --mailto $LOGWATCH_RECIPIENT" \
			>> /etc/cron.daily/logwatch
			chmod 744 /etc/cron.daily/logwatch
			;;
		"weekly" )
			notify 'inf' "Creating weekly cron job for logwatch reports"
			echo "#!/bin/bash" > /etc/cron.weekly/logwatch
			echo "/usr/sbin/logwatch --range 'between -7 days and -1 days' --hostname $HOSTNAME --mailto $LOGWATCH_RECIPIENT" \
			>> /etc/cron.weekly/logwatch
			chmod 744 /etc/cron.weekly/logwatch
			;;
	esac
}

function _setup_user_patches() {
	notify 'inf' 'Executing user-patches.sh'

	if [ -f /tmp/docker-mailserver/user-patches.sh ]; then
		chmod +x /tmp/docker-mailserver/user-patches.sh
		/tmp/docker-mailserver/user-patches.sh
		notify 'inf' "Executed 'config/user-patches.sh'"
	else
		notify 'inf' "No user patches executed because optional '/tmp/docker-mailserver/user-patches.sh' is not provided."
	fi
}

function _setup_environment() {
    notify 'task' 'Setting up /etc/environment'

    local banner="# docker environment"
    local var
    if ! grep -q "$banner" /etc/environment; then
        echo $banner >> /etc/environment
        for var in "VIRUSMAILS_DELETE_DELAY"; do
            echo "$var=${!var}" >> /etc/environment
        done
    fi
}

##########################################################################
# << Setup Stack
##########################################################################


##########################################################################
# >> Fix Stack
#
# Description: Place functions for temporary workarounds and fixes here
##########################################################################
function fix() {
	notify 'taskgrg' "Post-configuration checks..."
	for _func in "${FUNCS_FIX[@]}";do
		$_func
		[ $? != 0 ] && defunc
	done

        notify 'taskgrg' "Remove leftover pid files from a stop/start"
        rm -rf /var/run/*.pid /var/run/*/*.pid

	touch /dev/shm/supervisor.sock
}

function _fix_var_mail_permissions() {
	notify 'task' 'Checking /var/mail permissions'

	# Fix permissions, but skip this if 3 levels deep the user id is already set
	if [ `find /var/mail -maxdepth 3 -a \( \! -user 5000 -o \! -group 5000 \) | grep -c .` != 0 ]; then
		notify 'inf' "Fixing /var/mail permissions"
		chown -R 5000:5000 /var/mail
	else
		notify 'inf' "Permissions in /var/mail look OK"
		return 0
	fi
}

function _fix_cleanup_clamav() {
    notify 'task' 'Cleaning up disabled Clamav'
    rm -f /etc/logrotate.d/clamav-*
    rm -f /etc/cron.d/clamav-freshclam
}

function _fix_cleanup_spamassassin() {
    notify 'task' 'Cleaning up disabled spamassassin'
    rm -f /etc/cron.daily/spamassassin
}

##########################################################################
# << Fix Stack
##########################################################################


##########################################################################
# >> Misc Stack
#
# Description: Place functions that do not fit in the sections above here
##########################################################################
function misc() {
	notify 'taskgrp' 'Starting Misc'

	for _func in "${FUNCS_MISC[@]}";do
		$_func
		[ $? != 0 ] && defunc
	done
}

function _misc_save_states() {
	# consolidate all states into a single directory (`/var/mail-state`) to allow persistence using docker volumes
	statedir=/var/mail-state
	if [ "$ONE_DIR" = 1 -a -d $statedir ]; then
		notify 'inf' "Consolidating all state onto $statedir"
		for d in /var/spool/postfix /var/lib/postfix /var/lib/fail2ban /var/lib/dovecot; do
			dest=$statedir/`echo $d | sed -e 's/.var.//; s/\//-/g'`
			if [ -d $dest ]; then
				notify 'inf' "  Destination $dest exists, linking $d to it"
				rm -rf $d
				ln -s $dest $d
			elif [ -d $d ]; then
				notify 'inf' "  Moving contents of $d to $dest:" `ls $d`
				mv $d $dest
				ln -s $dest $d
			else
				notify 'inf' "  Linking $d to $dest"
				mkdir -p $dest
				ln -s $dest $d
			fi
		done

		notify 'inf' 'Fixing /var/mail-state/* permissions'
		chown -R clamav /var/mail-state/lib-clamav
		chown -R postfix /var/mail-state/lib-postfix
		chown -R postgrey /var/mail-state/lib-postgrey
		chown -R debian-spamd /var/mail-state/lib-spamassassin
		chown -R postfix /var/mail-state/spool-postfix

	fi
}

##########################################################################
# >> Start Daemons
##########################################################################
function start_daemons() {
	notify 'taskgrp' 'Starting mail server'

	for _func in "${DAEMONS_START[@]}";do
		$_func
		[ $? != 0 ] && defunc
	done
}

function _start_daemons_cron() {
	notify 'task' 'Starting cron' 'n'
	supervisorctl start cron
}

function _start_daemons_rsyslog() {
	notify 'task' 'Starting rsyslog ' 'n'
    supervisorctl start rsyslog
}

function _start_daemons_saslauthd() {
	notify 'task' 'Starting saslauthd' 'n'
    supervisorctl start "saslauthd_${SASLAUTHD_MECHANISMS}"
}

function _start_daemons_fail2ban() {
	notify 'task' 'Starting fail2ban ' 'n'
	touch /var/log/auth.log
	# Delete fail2ban.sock that probably was left here after container restart
	if [ -e /var/run/fail2ban/fail2ban.sock ]; then
		rm /var/run/fail2ban/fail2ban.sock
	fi
    supervisorctl start fail2ban
}

function _start_daemons_opendkim() {
	notify 'task' 'Starting opendkim ' 'n'
    supervisorctl start opendkim
}

function _start_daemons_opendmarc() {
	notify 'task' 'Starting opendmarc ' 'n'
    supervisorctl start opendmarc
}

function _start_daemons_postsrsd(){
	notify 'task' 'Starting postsrsd ' 'n'
	supervisorctl start postsrsd
}

function _start_daemons_postfix() {
	notify 'task' 'Starting postfix' 'n'
    supervisorctl start postfix
}

function _start_daemons_dovecot() {
	# Here we are starting sasl and imap, not pop3 because it's disabled by default

	notify 'task' 'Starting dovecot services' 'n'

	if [ "$ENABLE_POP3" = 1 ]; then
		notify 'task' 'Starting pop3 services' 'n'
		mv /etc/dovecot/protocols.d/pop3d.protocol.disab /etc/dovecot/protocols.d/pop3d.protocol
	fi

	if [ -f /tmp/docker-mailserver/dovecot.cf ]; then
		cp /tmp/docker-mailserver/dovecot.cf /etc/dovecot/local.conf
	fi

    supervisorctl start dovecot

	# @TODO fix: on integration test
	# doveadm: Error: userdb lookup: connect(/var/run/dovecot/auth-userdb) failed: No such file or directory
	# doveadm: Fatal: user listing failed

	#if [ "$ENABLE_LDAP" != 1 ]; then
		#echo "Listing users"
		#/usr/sbin/dovecot user '*'
	#fi
}

function _start_daemons_fetchmail() {
	notify 'task' 'Starting fetchmail' 'n'
	/usr/local/bin/setup-fetchmail
	supervisorctl start fetchmail
}

function _start_daemons_clamav() {
	notify 'task' 'Starting clamav' 'n'
    supervisorctl start clamav
}

function _start_daemons_postgrey() {
	notify 'task' 'Starting postgrey' 'n'
	rm -f /var/run/postgrey/postgrey.pid
    supervisorctl start postgrey
}


##########################################################################
# << Start Daemons
##########################################################################


##########################################################################
# Start check for update postfix-accounts and postfix-virtual
##########################################################################

function _start_changedetector() {
	notify 'task' 'Starting changedetector' 'n'
    supervisorctl start changedetector
}


# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !  CARE --> DON'T CHANGE, unless you exactly know what you are doing
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# >>

. /usr/local/bin/helper_functions.sh

if [[ ${DEFAULT_VARS["DMS_DEBUG"]} == 1 ]]; then
notify 'taskgrp' ""
notify 'taskgrp' "#"
notify 'taskgrp' "#"
notify 'taskgrp' "# ENV"
notify 'taskgrp' "#"
notify 'taskgrp' "#"
notify 'taskgrp' ""
printenv
fi

notify 'taskgrp' ""
notify 'taskgrp' "#"
notify 'taskgrp' "#"
notify 'taskgrp' "# docker-mailserver"
notify 'taskgrp' "#"
notify 'taskgrp' "#"
notify 'taskgrp' ""

register_functions

check
setup
fix
misc
start_daemons

notify 'taskgrp' ""
notify 'taskgrp' "#"
notify 'taskgrp' "# $HOSTNAME is up and running"
notify 'taskgrp' "#"
notify 'taskgrp' ""

touch /var/log/mail/mail.log
tail -fn 0 /var/log/mail/mail.log


# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !  CARE --> DON'T CHANGE, unless you exactly know what you are doing
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# <<

exit 0

