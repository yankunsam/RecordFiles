FROM ubuntu:16.04

RUN apt-get update && apt-get install -y git make gcc libssl1.0.0 libssl-dev
RUN cd /home/ && git clone https://github.com/yankunsam/Hachi.git
RUN cd /home/Hachi/tpm/src/ && make && rm *.o 
RUN cd /home/Hachi/tss/utils/ && make && rm *.o

RUN apt-get install -y libjson-c-dev libjson-c2 && ln -s /usr/include/json-c /usr/include/json
#mysql-server : password root 123456
RUN apt-get install -y mysql-client libmysqlclient-dev mysql-server && service mysql start
RUN apt-get install -y php7.0 php7.0-mysql
RUN apt-get install -y apache2
RUN mkdir /var/www/html/acs && chmod 777 /var/www/html/acs
RUN mysql> create database tpm2;
RUN mysql> grant all privileges on tpm2.* to ''@'localhost';
RUN mysql -D tpm2 < dbinit.sql



# adduser octa 123
RUN cd /home/Hachi/acs/acs/ && make
#RUN cd /home/ && git clone https://github.com/yankunsam/openssl.git
RUN openssl genrsa -out cakey.pem -aes256 -passout pass:rrrr 2048
# interactive should automate
RUN openssl req -new -x509 -key cakey.pem -out cacert.pem -days 3650
RUN cp cacert.pem ../utils/certificates/
RUN openssl genpkey -out cakeyecc.pem -outform PEM -pass pass:rrrr -aes256 -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve
RUN openssl req -new -x509 -key cakeyecc.pem -out cacertecc.pem -days 3650
RUN cp cacert.pem ../utils/certificates/
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
