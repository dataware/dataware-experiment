#!/bin/sh
ROOT_DIR=~/dataware.client-skeleton
PKG_DIR=$ROOT_DIR/pkg/package_files
cd $ROOT_DIR/src
rm -rf deb_dist
python setup.py --command-packages=stdeb.command sdist_dsc
cd deb_dist/dataware-client-skeleton-0.1/debian
cp $PKG_DIR/control ./
cp $PKG_DIR/config ./
cp $PKG_DIR/postinst ./
cp $PKG_DIR/rules ./
cp $PKG_DIR/dirs ./
cd ..
#cp $PKG_DIR/mysql.sql ./
dpkg-buildpackage -rfakeroot -uc -us
cd debian/dataware-client-skeleton
mkdir -p var/dataware-client-skeleton
mkdir -p etc/dataware
mkdir -p var/log/dataware
chmod -R 777 var/log/dataware
mv ../../dataware-client-skeleton/static ./var/dataware-client-skeleton
mv ../../dataware-client-skeleton/templates  ./var/dataware-client-skeleton
cp ../../dataware-client-skeleton/client.cfg ./usr/share/pyshared/dataware-client-skeleton
cd ..
dpkg --build dataware-client-skeleton dataware-client-skeleton.deb
cp dataware-client-skeleton.deb $ROOT_DIR 
