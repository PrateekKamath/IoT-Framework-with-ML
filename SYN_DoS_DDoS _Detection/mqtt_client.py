import asyncio
import websockets
import paho.mqtt.client as mqtt

async def handle_websocket(websocket, path):
    all_messages = []

    async def send_messages(websocket):
        while True:
            if all_messages:
                messages_to_send = "<br>".join(f"{msg}" for msg in all_messages)
                await websocket.send(messages_to_send)
            await asyncio.sleep(1)  # Adjust as needed

    async def connect_mqtt():
        async def on_connect(client, userdata, flags, rc):
            print("Connected with result code " + str(rc))
            client.subscribe("packet_capture_results")

        async def on_message(client, userdata, msg):
            message = msg.payload.decode()  # Extract message
            all_messages.append(message)  # Store message

        client = mqtt.Client()
        client.on_connect = on_connect
        client.on_message = on_message

        client.connect("test.mosquitto.org", 1883, 60)
        client.loop_start()

    await asyncio.gather(connect_mqtt(), send_messages(websocket))

start_server = websockets.serve(handle_websocket, "localhost", 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
