FROM ubuntu:16.04

RUN apt-get update && apt-get install -y git make gcc libssl1.0.0 libssl-dev
RUN cd /home/ && git clone https://github.com/yankunsam/Hachi.git
RUN cd /home/Hachi/tpm/src/ && make && rm *.o 
RUN cd /home/Hachi/tss/utils/ && make && rm *.o

RUN apt-get install -y libjson-c-dev libjson-c2 && ln -s /usr/include/json-c /usr/include/json
#mysql-server : password root 123456
RUN apt-get install -y mysql-client libmysqlclient-dev mysql-server && service mysql start
RUN apt-get install -y php7.0 php7.0-mysql
RUN mysql> create database tpm2;
RUN mysql> grant all privileges on tpm2.* to ''@'localhost';
RUN mysql -D tpm2 < dbinit.sql
# adduser octa 123
RUN cd /home/Hachi/acs/acs/

#RUN mkdir /var/run/sshd
#RUN echo 'root:screencast' | chpasswd
#RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
#
## SSH login fix. Otherwise user is kicked off after login
#RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
#
#ENV NOTVISIBLE "in users profile"
#RUN echo "export VISIBLE=now" >> /etc/profile
#
#EXPOSE 22
#CMD ["/usr/sbin/sshd", "-D"]
