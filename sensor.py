import asyncio
import logging
import re

import aiohttp

from hexdump import hexdump
from time import time
from Crypto.Cipher import AES

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription, SensorDeviceClass, SensorStateClass
from homeassistant.const import EntityCategory
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo

from .const import DOMAIN, CONF_RELAY, CONF_RELAY_REPLIES


SERVER_HOST = '0.0.0.0'
SERVER_PORT = 20001

# Relaying to GoodWe (SEMS) is switched on in the integration's options (Configure)
GOODWE_HOST = 'tcp.goodwe-power.com'
GOODWE_PORT = 20001
GOODWE_RELAY_TIMEOUT = 10       # Seconds to connect / wait for a reply
GOODWE_DOH_URL = 'https://1.1.1.1/dns-query'  # Resolve GOODWE_HOST here, bypassing the local DNS rewrite
GOODWE_DNS_TTL = 3600

AES_KEY = b'\xff' * 16

SENSOR_TIMEOUT = 300

log = logging.getLogger(__package__)


async def async_setup_entry( hass, config_entry, async_add_entities ):

    device_sensors = {}
    device_timestamps = {}
    relay_state = { 'ip': None, 'resolved_at': 0, 'failing': False }

    async def start_server():
        server = await asyncio.start_server(
            handle_packet,
            SERVER_HOST,
            SERVER_PORT
        )
        addr = server.sockets[0].getsockname()
        log.debug(f'Started {DOMAIN} on {addr}')
        return server


    async def read_full_packet( reader, idle=1.0, initial=30.0 ):
        """Accumulate TCP segments until the peer pauses or closes."""
        packet = await asyncio.wait_for( reader.read(1024), initial )
        while packet:
            try:
                chunk = await asyncio.wait_for( reader.read(1024), idle )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            packet += chunk
        return packet


    async def handle_packet( reader, writer ):
        addr = writer.get_extra_info('peername')
        try:
            await process_packet( reader, writer, addr )
        except (ConnectionResetError, BrokenPipeError) as err:
            log.warning(f"Connection lost from {addr}: {type(err).__name__}")
        except asyncio.TimeoutError:
            log.warning(f"Idle connection from {addr}, closing")
        except (UnicodeDecodeError, ValueError, IndexError) as err:
            log.warning(f"Malformed packet from {addr}: {type(err).__name__}: {err}")
        except Exception:
            log.exception(f"Unhandled error while processing packet from {addr}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


    async def resolve_goodwe_host():
        """Look up GoodWe's real server over DNS-over-HTTPS, so a local DNS
        rewrite pointing GOODWE_HOST at HA doesn't make the relay loop back to itself."""
        if relay_state['ip'] and time() - relay_state['resolved_at'] < GOODWE_DNS_TTL:
            return relay_state['ip']
        try:
            session = async_get_clientsession( hass )
            async with session.get(
                GOODWE_DOH_URL,
                params = { 'name': GOODWE_HOST, 'type': 'A' },
                headers = { 'accept': 'application/dns-json' },
                timeout = aiohttp.ClientTimeout( total=GOODWE_RELAY_TIMEOUT )
            ) as resp:
                data = await resp.json( content_type=None )
            ips = [ answer['data'] for answer in data.get('Answer', []) if answer.get('type') == 1 ]
            if ips:
                relay_state['ip'] = ips[0]
                relay_state['resolved_at'] = time()
                log.debug(f"Resolved {GOODWE_HOST} to {ips[0]}")
        except Exception as err:
            log.debug(f"Could not resolve {GOODWE_HOST}: {type(err).__name__}: {err}")
        return relay_state['ip']  # Last known address if the lookup failed


    async def relay_packet( packet, writer, addr ):
        """Forward a packet to GoodWe's server. Failures are logged, never raised,
        so local processing doesn't depend on the internet or GoodWe."""
        gw_writer = None
        try:
            ip = await resolve_goodwe_host()
            if ip is None:
                raise OSError(f"no address for {GOODWE_HOST}")
            gw_reader, gw_writer = await asyncio.wait_for(
                asyncio.open_connection( ip, GOODWE_PORT ), GOODWE_RELAY_TIMEOUT )
            gw_writer.write( packet )
            await gw_writer.drain()
            log.debug(f"Relayed packet from {addr} to {[GOODWE_HOST, ip, GOODWE_PORT]}")
            reply = await asyncio.wait_for( gw_reader.read(1024), GOODWE_RELAY_TIMEOUT )
            log.debug(f"Received reply:\n{hexdump(reply)}")
            if reply and config_entry.options.get( CONF_RELAY_REPLIES, False ):
                writer.write( reply )
                await writer.drain()
            if relay_state['failing']:
                log.info(f"Relay to {GOODWE_HOST} working again")
                relay_state['failing'] = False
        except (OSError, asyncio.TimeoutError) as err:
            # Warn once per outage, not for every packet
            level = logging.DEBUG if relay_state['failing'] else logging.WARNING
            log.log( level, f"Relay to {GOODWE_HOST} failed: {type(err).__name__}: {err}")
            relay_state['failing'] = True
        finally:
            if gw_writer is not None:
                gw_writer.close()
                try:
                    await gw_writer.wait_closed()
                except Exception:
                    pass


    async def process_packet( reader, writer, addr ):
        packet = await read_full_packet( reader )
        log.debug(f"\n\n\nReceived packet from {addr}:\n{hexdump(packet)}")

        if len(packet) == 0:
            log.debug(f"Empty packet from {addr}")
            return

        try:
            await parse_packet( packet, addr )
        finally:
            # Relay after parsing, so HA updates first and a slow or
            # unreachable GoodWe server can't hold up local data
            if config_entry.options.get( CONF_RELAY, False ):
                await relay_packet( packet, writer, addr )


    async def parse_packet( packet, addr ):
        if len(packet) < 0x46:
            log.warning(f"Truncated packet ({len(packet)} bytes) from {addr}, discarding")
            return

        packet_type = packet[ 10 : 12 ]
        model = packet[ 14 : 22 ].decode('ascii')
        serial = packet[ 22 : 30 ].decode('ascii')
        log.debug(f"packet_type: {packet_type} model: {model} serial: {serial}")

        iv = packet[ 0x1e : 0x2e ]
        ciphertext = packet[ 0x34 : -2 ]
        plaintext = b''
        if len(ciphertext) >= 16 and len(ciphertext) % 16 == 0:
            cipher = AES.new( AES_KEY, AES.MODE_CBC, IV=iv )
            plaintext = cipher.decrypt( ciphertext )
            log.debug(f"plaintext:\n{hexdump(plaintext)}")
        else:
            log.warning(f"Undecryptable ciphertext ({len(ciphertext)} bytes) from {addr}, discarding")
            return

        if packet_type == b'\03\04' and model in ('93000HKU', '91000HKU'):
            if len(plaintext) < 0x70:
                log.warning(f"Short plaintext ({len(plaintext)} bytes) from {addr}, discarding")
                return
            if int.from_bytes( plaintext[ 0x39 : 0x3b ], signed=True ) == 0:
                log.warning(f"Zero mains voltage from {addr}, discarding frame")
                return
            await handle_93000HKU_meter_metrics( packet, plaintext )
        elif packet_type == b'\01\04' and model == '58000DTA':
            await handle_58000DTA_inverter_metrics( packet, plaintext )
        else:
            log.warning(f"Unknown packet {packet_type} from {addr}:\nRaw:\n{hexdump(packet)}\nPlain:\n{hexdump(plaintext)}")


    async def handle_93000HKU_meter_metrics( packet, plaintext ):
        serial = packet[ 22 : 30 ].decode('ascii')

        if serial not in device_sensors:
            device = DeviceInfo(
                manufacturer = 'GoodWe',
                model = 'HomeKit',
                model_id = 'HK3000',
                name = 'Energy Meter',
                serial_number = serial,
                identifiers = {( DOMAIN, serial )}
            )
            device_sensors[ serial ] = [
                EnergySensor(   device, 'L1 Energy Exported',      0x07,        ),
                EnergySensor(   device, 'L2 Energy Exported',      0x0d,        ),
                EnergySensor(   device, 'L3 Energy Exported',      0x13,        ),
                EnergySensor(   device, 'Total Energy Exported',   0x19, primary=True ),
                EnergySensor(   device, 'L1 Energy Imported',      0x1f,        ),
                EnergySensor(   device, 'L2 Energy Imported',      0x25,        ),
                EnergySensor(   device, 'L3 Energy Imported',      0x2b,        ),
                EnergySensor(   device, 'Total Energy Imported',   0x31, primary=True ),
                VoltageSensor(  device, 'L1 Voltage',              0x39,        ),
                VoltageSensor(  device, 'L2 Voltage',              0x3b,        ),
                VoltageSensor(  device, 'L3 Voltage',              0x3d,        ),
                CurrentSensor(  device, 'L1 Peak Current',         0x41, scale=.01 ),
                CurrentSensor(  device, 'L2 Peak Current',         0x45, scale=.01 ),
                CurrentSensor(  device, 'L3 Peak Current',         0x49, scale=.01 ),
                PowerSensor(    device, 'L1 Export Power',         0x4b,        ),
                PowerSensor(    device, 'L2 Export Power',         0x4f,        ),
                PowerSensor(    device, 'L3 Export Power',         0x53,        ),
                PowerSensor(    device, 'Total Export Power',      0x57, primary=True ),
                BinarySensor(   device, '0x00-0x06',               0x00, 7      ),
                BinarySensor(   device, '0x0b-0x0c',               0x0b, 2      ),
                BinarySensor(   device, '0x11-0x12',               0x11, 2      ),
                BinarySensor(   device, '0x17-0x18',               0x17, 2      ),
                BinarySensor(   device, '0x1d-0x1e',               0x1d, 2      ),
                BinarySensor(   device, '0x23-0x24',               0x23, 2      ),
                BinarySensor(   device, '0x29-0x2a',               0x29, 2      ),
                BinarySensor(   device, '0x2f-0x30',               0x2f, 2      ),
                BinarySensor(   device, '0x35-0x36',               0x35, 2      ),
                BinarySensor(   device, '0x37-0x38',               0x37, 2      ),
                BinarySensor(   device, '0x5b-0x6f',               0x5b, 21     ),
            ]
            async_add_entities( device_sensors[serial] )

        for sensor in device_sensors[ serial ]:
            if sensor.enabled:
                sensor.write( plaintext )

        device_timestamps[ serial ] = time()


    async def handle_58000DTA_inverter_metrics( packet, plaintext ):
        serial = packet[ 22 : 30 ].decode('ascii')

        if serial not in device_sensors:
            device = DeviceInfo(
                manufacturer = 'GoodWe',
                model = 'DT Series',
                model_id = 'GW8KAU-DT',
                name = 'Solar Inverter',
                serial_number = serial,
                identifiers = {( DOMAIN, serial )}
            )
            device_sensors[ serial ] = [
                BinarySensor(       device, '0x00-0x14',        0x00, 0x15  ),
                BinarySensor(       device, 'Timestamp',        0x15, 6     ),
                VoltageSensor(      device, 'PV1 Voltage',      0x1b        ),
                CurrentSensor(      device, 'PV1 Current',      0x1d        ),
                VoltageSensor(      device, 'PV2 Voltage',      0x1f        ),
                CurrentSensor(      device, 'PV2 Current',      0x21        ),
                BinarySensor(       device, '0x23-0x38',        0x23, 0x16  ),
                VoltageSensor(      device, 'L1 Voltage',       0x39        ),
                VoltageSensor(      device, 'L2 Voltage',       0x3b        ),
                VoltageSensor(      device, 'L3 Voltage',       0x3d        ),
                CurrentSensor(      device, 'L1 Current',       0x3f        ),
                CurrentSensor(      device, 'L2 Current',       0x41        ),
                CurrentSensor(      device, 'L3 Current',       0x43        ),
                FrequencySensor(    device, 'L1 Frequency',     0x45        ),
                FrequencySensor(    device, 'L2 Frequency',     0x47        ),
                FrequencySensor(    device, 'L3 Frequency',     0x49        ),
                PowerSensor(        device, 'Total Power',      0x4b, primary=True ),
                BinarySensor(       device, 'Work Mode',        0x4f        ),
                BinarySensor(       device, '0x51-0x56',        0x51, 6     ),
                BinarySensor(       device, '0x57-0x66',        0x57, 0x10  ),
                TemperatureSensor(  device, 'Temperature',      0x67        ),
                BinarySensor(       device, '0x69-0x6c',        0x69, 4     ),
                EnergySensor(       device, 'Todays Energy',    0x6d, 2, scale=.1, primary=True ),
                EnergySensor(       device, 'Total Energy',     0x6f, scale=.1, primary=True ),
                DurationSensor(     device, 'Runtime',          0x73, 4     ),
                BinarySensor(       device, '0x77-0x7e',        0x77, 6     ),
                BinarySensor(       device, 'FunBit',           0x7d        ),
                VoltageSensor(      device, 'Bus Voltage',      0x7f        ),
                VoltageSensor(      device, 'Nbus Voltage',     0x81        ),
                BinarySensor(       device, '0x83-0x86',        0x83, 4     ),
                IntSensor(          device, '0x87-0x88',        0x87, 2     ),
                BinarySensor(       device, '0x89-0x90',        0x89, 8     ),
                IntSensor(          device, '0x91-0x92',        0x91        ),
                BinarySensor(       device, '0x93-0x96',        0x93, 4     ),
                CurrentSensor(      device, 'PV1 Current again',0x97, disabled=True ),
                CurrentSensor(      device, 'PV2 Current again',0x99, disabled=True ),
                BinarySensor(       device, '0x9b-0x9e',        0x9b, 4     ),
                BinarySensor(       device, '0x9f-0xa2',        0x9f, 4     ),
                TemperatureSensor(  device, '0xa3-0xa4',        0xa3, disabled=True ), # Core temperature?
                BinarySensor(       device, '0xa5-0xa6',        0xa5        ),
                IntSensor(          device, '0xa7-0xa8',        0xa7        ),
                BinarySensor(       device, '0xa9-0xaa',        0xa9        ),
                IntSensor(          device, '0xab-0xac',        0xab        ), # Fan active?
                BinarySensor(       device, '0xad-0xb0',        0xad, 4     ),
                IntSensor(          device, '0xb1-0xb2',        0xb1        ),
                BinarySensor(       device, '0xb3-0xcc',        0xb3, 0x1a  ),
                BinarySensor(       device, '0xcd-0x1ff',       0xcd, 0x43  ),
            ]
            async_add_entities( device_sensors[serial] )

        for sensor in device_sensors[ serial ]:
            if sensor.enabled:
                sensor.write( plaintext )

        device_timestamps[ serial ] = time()


    class GoodweSensor( SensorEntity ):
        byte_length = 2
        scale_factor = 1

        def __init__( self, device, name, offset, length=None, scale=None, primary=False, disabled=None ):
            self._attr_device_info = device
            self.entity_description = SensorEntityDescription(
                key = re.sub('[^0-9a-z_]', '', re.sub('[ \\-]', '_', name.lower())),
                has_entity_name = True,
                name = name,
                device_class = self.device_class,
                state_class = self.state_class,
                native_unit_of_measurement = self.native_unit_of_measurement,
                suggested_unit_of_measurement = self.suggested_unit_of_measurement
            )
            self._attr_unique_id = f"{device['serial_number']}_{self.entity_description.key}"
            self._attr_entity_category = None if primary else EntityCategory.DIAGNOSTIC
            self.byte_offset = offset
            if length is not None:
                self.byte_length = length
            if scale is not None:
                self.scale_factor = scale
            if disabled is not None:
                self.entity_registry_enabled_default = not disabled

        def write( self, data ):
            self._write( data )
            self._attr_available = True
            self.async_write_ha_state()
            log.debug( f"{self.name+':':<24} {self.native_value}" )

        def _write( self, data ):
            self._attr_native_value = self.scale_factor * int.from_bytes( data[ self.byte_offset : self.byte_offset + self.byte_length ], signed=True )

        async def async_update( self ):
            if not self.available:
                return
            if time() - device_timestamps[ self.device_info['serial_number'] ] > SENSOR_TIMEOUT:
                self._attr_available = False


    class EnergySensor( GoodweSensor ):
        device_class = SensorDeviceClass.ENERGY
        state_class = SensorStateClass.TOTAL_INCREASING
        native_unit_of_measurement = 'kWh'
        byte_length = 4
        scale_factor = .01

    class VoltageSensor( GoodweSensor ):
        device_class = SensorDeviceClass.VOLTAGE
        state_class = SensorStateClass.MEASUREMENT
        native_unit_of_measurement = 'V'
        scale_factor = 0.1

    class CurrentSensor( GoodweSensor ):
        device_class = SensorDeviceClass.CURRENT
        state_class = SensorStateClass.MEASUREMENT
        native_unit_of_measurement = 'A'
        scale_factor = .1

    class PowerSensor( GoodweSensor ):
        device_class = SensorDeviceClass.POWER
        state_class = SensorStateClass.MEASUREMENT
        native_unit_of_measurement = 'W'
        byte_length = 4

    class FrequencySensor( GoodweSensor ):
        device_class = SensorDeviceClass.FREQUENCY
        state_class = SensorStateClass.MEASUREMENT
        native_unit_of_measurement = 'Hz'
        scale_factor = 0.01

    class TemperatureSensor( GoodweSensor ):
        device_class = SensorDeviceClass.TEMPERATURE
        state_class = SensorStateClass.MEASUREMENT
        native_unit_of_measurement = '°C'
        scale_factor = 0.1

    class DurationSensor( GoodweSensor ):
        device_class = SensorDeviceClass.DURATION
        state_class = SensorStateClass.TOTAL_INCREASING
        native_unit_of_measurement = 'h'

    class BinarySensor( GoodweSensor ):
        entity_registry_enabled_default = False
        def _write( self, data ):
            self._attr_native_value = data[ self.byte_offset : self.byte_offset + self.byte_length ].hex(' ')

    class IntSensor( GoodweSensor ):
        entity_registry_enabled_default = False
        state_class = SensorStateClass.MEASUREMENT


    await start_server()
