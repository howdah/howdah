# Milestone-0 lab image: PHP 5.4 -- CentOS 7 stock packages.
#
# Not a production image. PHP 5.4 has no official Docker Hub image and is
# NOT built from source here; per the howdah 0.1 design, CentOS 7's own
# php-5.4.16 package is the real-world deployment target for this version,
# so the lab reproduces exactly that: yum-installed PHP 5.4.16 on a stock
# centos:7 base. Provides build tools so the throwaway milestone-0 spike
# extension (lab/spike/probe.c) can be compiled against it. See
# docs/superpowers/specs/milestone-0-findings.md.

FROM centos:7

# CentOS 7 is EOL; mirrorlist.centos.org is gone. Point yum at the frozen
# vault mirror instead.
RUN sed -i 's|mirrorlist=|#mirrorlist=|g; s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/*.repo \
    && yum install -y php php-cli php-fpm php-devel gcc make curl \
    && yum clean all

CMD ["sleep", "infinity"]
