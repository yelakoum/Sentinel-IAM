package Server.Log;

import com.google.gson.Gson;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

/**
 * Producer class responsible for sending security logs to a RabbitMQ message broker.
 * This acts as the "Mailman" sending parsed logs to the queue for external systems to consume.
 */
public class LogProducer {
    
    /**
     * The name of the RabbitMQ queue where alerts will be published.
     */
    private static final String QUEUE_NAME = "security_alerts";
    
    private ConnectionFactory connectionFactory;
    private Gson gson;

    /**
     * Initializes the LogProducer, setting up the RabbitMQ connection factory
     * and the JSON converter.
     */
    public LogProducer() {
        // 1. Configure the connection to the RabbitMQ server (localhost)
        connectionFactory = new ConnectionFactory();
        connectionFactory.setHost("localhost"); 
        
        // 2. Initialize Gson for Java Object to JSON conversion
        gson = new Gson();
    }

    /**
     * Serializes a LogSecurity object to JSON and publishes it to the RabbitMQ queue.
     * Uses a try-with-resources block to ensure the network connection is safely closed.
     *
     * @param log The parsed security log object containing attack details.
     */
    public void sendAlert(LogSecurity log) {
        // The try-with-resources automatically closes the Connection and Channel
        // once the block is finished, preventing memory leaks.
        try (Connection connection = connectionFactory.newConnection();
             Channel channel = connection.createChannel()) {

            // 1. Ensure the queue exists before sending a message
            channel.queueDeclare(QUEUE_NAME, false, false, false, null);

            // 2. Convert the Java object (log) into a JSON formatted string
            String messageJson = gson.toJson(log);

            // 3. Publish the physical message to the queue
            channel.basicPublish("", QUEUE_NAME, null, messageJson.getBytes("UTF-8"));
            
            System.out.println("[RABBITMQ] Alert successfully posted: " + messageJson);

        } catch (Exception e) {
            System.err.println("Error connecting to RabbitMQ: " + e.getMessage());
        }
    }
}