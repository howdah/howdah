# EL7 rpmbuild environment (oldest rpm we target => rpms install on EL7..EL9).
# CentOS 7 is EOL: point yum at vault.centos.org.
FROM centos:7
RUN sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-*.repo \
 && yum install -y rpm-build redhat-rpm-config file && yum clean all
