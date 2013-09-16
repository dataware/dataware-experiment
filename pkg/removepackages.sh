#!/bin/sh
apt-get -y remove --purge dataware-client-skeleton
rm -rf /usr/share/pyshared/dataware-client-skeleton
apt-get -y --purge autoremove
ucf --purge /etc/dbconfig-common/dataware-client-skeleton.conf
ucf --purge /etc/dataware/client_config.cfg
