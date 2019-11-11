# NTPClient

1. 引入依赖

    ```xml
    <dependency>
        <groupId>commons-net</groupId>
        <artifactId>commons-net</artifactId>
        <version>3.6</version>
    </dependency>
    ```

1. 客户端请求NTP服务器时间

    ```java
    import org.apache.commons.net.ntp.NTPUDPClient;
    import org.apache.commons.net.ntp.TimeInfo;
    import org.apache.commons.net.ntp.TimeStamp;

    import java.io.IOException;
    import java.net.InetAddress;
    import java.text.DateFormat;
    import java.text.SimpleDateFormat;
    import java.util.Date;

    public class NtpDemo {

        public static void main(String[] args) throws IOException {
            NTPUDPClient timeClient = new NTPUDPClient();
            String timeServerUrl = "127.0.0.1";
            InetAddress timeServerAddress = InetAddress.getByName(timeServerUrl);
            TimeInfo timeInfo = timeClient.getTime(timeServerAddress);
            TimeStamp timeStamp = timeInfo.getMessage().getTransmitTimeStamp();
            Date date = timeStamp.getDate();
            System.out.println(date);
            DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
            System.out.println(dateFormat.format(date));
        }
    }
    ```

1. getTime实现

    ```java
    // 默认访问123端口
    public TimeInfo getTime(InetAddress host) throws IOException {
        return this.getTime(host, 123);
    }

    public TimeInfo getTime(InetAddress host, int port) throws IOException {
        if (!this.isOpen()) {
            this.open();
        }

        NtpV3Packet message = new NtpV3Impl();
        message.setMode(3);
        message.setVersion(this._version);
        // 使用UDP服务
        DatagramPacket sendPacket = message.getDatagramPacket();
        sendPacket.setAddress(host);
        sendPacket.setPort(port);
        NtpV3Packet recMessage = new NtpV3Impl();
        DatagramPacket receivePacket = recMessage.getDatagramPacket();
        TimeStamp now = TimeStamp.getCurrentTime();
        message.setTransmitTime(now);
        this._socket_.send(sendPacket);
        this._socket_.receive(receivePacket);
        long returnTime = System.currentTimeMillis();
        TimeInfo info = new TimeInfo(recMessage, returnTime, false);
        return info;
    }
    ```
