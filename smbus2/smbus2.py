"""usmbus2 - A MicroPython drop-in replacement for smbus-cffi/smbus-python"""
# The MIT License (MIT)
# Copyright (c) 2020 Karl-Petter Lindegaard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
from fcntl import ioctl
# from ctypes import c_uint32, c_uint8, c_uint16, c_char, POINTER, Structure, Array, Union, create_string_buffer, string_at
import uctypes # import c_uint32, c_uint8, c_uint16, c_char, POINTER, Structure, Array, Union, create_string_buffer, string_at

def POINTER(descriptor_class, offset):
    return (uctypes.PTR | offset, descriptor_class.desc)

# Commands from uapi/linux/i2c-dev.h
I2C_SLAVE = 0x0703  # Use this slave address
I2C_SLAVE_FORCE = 0x0706  # Use this slave address, even if it is already in use by a driver!
I2C_FUNCS = 0x0705  # Get the adapter functionality mask
I2C_RDWR = 0x0707  # Combined R/W transfer (one STOP only)
I2C_SMBUS = 0x0720  # SMBus transfer. Takes pointer to i2c_smbus_ioctl_data
I2C_PEC = 0x0708  # != 0 to use PEC with SMBus

# SMBus transfer read or write markers from uapi/linux/i2c.h
I2C_SMBUS_WRITE = 0
I2C_SMBUS_READ = 1

# Size identifiers uapi/linux/i2c.h
I2C_SMBUS_QUICK = 0
I2C_SMBUS_BYTE = 1
I2C_SMBUS_BYTE_DATA = 2
I2C_SMBUS_WORD_DATA = 3
I2C_SMBUS_PROC_CALL = 4
I2C_SMBUS_BLOCK_DATA = 5  # This isn't supported by Pure-I2C drivers with SMBUS emulation, like those in RaspberryPi, OrangePi, etc :(
I2C_SMBUS_BLOCK_PROC_CALL = 7  # Like I2C_SMBUS_BLOCK_DATA, it isn't supported by Pure-I2C drivers either.
I2C_SMBUS_I2C_BLOCK_DATA = 8
I2C_SMBUS_BLOCK_MAX = 32

# To determine what functionality is present (uapi/linux/i2c.h)
try:
    from enum import IntFlag
except ImportError:
    IntFlag = int


class I2cFunc(IntFlag):
    """
    These flags identify the operations supported by an I2C/SMBus device.

    You can test these flags on your `smbus.funcs`

    On newer python versions, I2cFunc is an IntFlag enum, but it
    falls back to class with a bunch of int constants on older releases.
    """
    I2C = 0x00000001
    ADDR_10BIT = 0x00000002
    PROTOCOL_MANGLING = 0x00000004  # I2C_M_IGNORE_NAK etc.
    SMBUS_PEC = 0x00000008
    NOSTART = 0x00000010  # I2C_M_NOSTART
    SLAVE = 0x00000020
    SMBUS_BLOCK_PROC_CALL = 0x00008000  # SMBus 2.0
    SMBUS_QUICK = 0x00010000
    SMBUS_READ_BYTE = 0x00020000
    SMBUS_WRITE_BYTE = 0x00040000
    SMBUS_READ_BYTE_DATA = 0x00080000
    SMBUS_WRITE_BYTE_DATA = 0x00100000
    SMBUS_READ_WORD_DATA = 0x00200000
    SMBUS_WRITE_WORD_DATA = 0x00400000
    SMBUS_PROC_CALL = 0x00800000
    SMBUS_READ_BLOCK_DATA = 0x01000000
    SMBUS_WRITE_BLOCK_DATA = 0x02000000
    SMBUS_READ_I2C_BLOCK = 0x04000000  # I2C-like block xfer
    SMBUS_WRITE_I2C_BLOCK = 0x08000000  # w/ 1-byte reg. addr.
    SMBUS_HOST_NOTIFY = 0x10000000

    SMBUS_BYTE = 0x00060000
    SMBUS_BYTE_DATA = 0x00180000
    SMBUS_WORD_DATA = 0x00600000
    SMBUS_BLOCK_DATA = 0x03000000
    SMBUS_I2C_BLOCK = 0x0c000000
    SMBUS_EMUL = 0x0eff0008


# i2c_msg flags from uapi/linux/i2c.h
I2C_M_RD = 0x0001


#############################################################
# Type definitions as in i2c.h

I2C_SMBUS_BLOCK_MAX = 32
class union_i2c_smbus_data():
    desc = {
        "byte":   uctypes.UINT8  | 0,
        "word":   uctypes.UINT16 | 0,
        "block": (uctypes.ARRAY  | 0,  I2C_SMBUS_BLOCK_MAX+2 | uctypes.UINT8)
    }

    def __init__(self, byte=None, word=None, block=None):
        self.mem = bytearray(uctypes.sizeof(self.desc))
        self.mv  = memoryview(self.mem)
        self.data = uctypes.struct(uctypes.addressof(self.mv), self.desc, uctypes.NATIVE)

        if byte is not None:
            self.data.byte = byte
        elif word is not None:
            self.data.word = word
        elif block is not None:
            self.data.block = block

    def addr(self):
        return uctypes.addressof(self.mv)

class i2c_smbus_ioctl_data():
    """
    As defined in ``i2c-dev.h``.
    """
    desc = {
        'read_write':  uctypes.UINT8  | 0,
        'command':     uctypes.UINT8  | 1,
        'size':        uctypes.UINT32 | 4,
        'data':       (uctypes.PTR    | 8, union_i2c_smbus_data.desc),
        'data__':      uctypes.INT32  | 8 # data can't be set, so use this instead
    }

    def __init__(self, read_write=I2C_SMBUS_READ, command=0, size=I2C_SMBUS_BYTE_DATA):
        self.mem = bytearray(uctypes.sizeof(self.desc))
        self.mv  = memoryview(self.mem)
        self.data = uctypes.struct(uctypes.addressof(self.mv), self.desc, uctypes.NATIVE)

        self.u = union_i2c_smbus_data()

        self.data.read_write = read_write
        self.data.command    = command
        self.data.size       = size
        self.data.data__     = self.u.addr()

    def addr(self):
        return uctypes.addressof(self.mv)


    @staticmethod
    def create(read_write=I2C_SMBUS_READ, command=0, size=I2C_SMBUS_BYTE_DATA):
        return i2c_smbus_ioctl_data( read_write=read_write, command=command, size=size)


#############################################################
# Type definitions for i2c_rdwr combined transactions


class i2c_msg():
    """
    As defined in ``i2c.h``.
    """
    desc = {
        'addr':  uctypes.UINT16 | 0,
        'flags': uctypes.UINT16 | 2,
        'len':   uctypes.UINT16 | 4,
        'buf':  (uctypes.PTR    | 8, uctypes.UINT8),
        'buf__': uctypes.INT32  | 8
    }

    def __init__(self, addr, flags, length = None, buf = None):
        self.mem = bytearray(uctypes.sizeof(self.desc))
        self.mv  = memoryview(self.mem)
        self.data = uctypes.struct(uctypes.addressof(self.mv), self.desc, uctypes.NATIVE)

        assert length is not None or buf is not None

        if length is not None:
            self.child = bytearray(length)
        else: # buf is not None
            self.child = buf
            length = len(buf)

        self.buf = memoryview(self.child)

        self.data.addr  = addr
        self.data.flags = flags
        self.data.len   = length
        self.data.buf__ = uctypes.addressof(self.buf)

    def __iter__(self):
        """ Iterator / Generator

        :return: iterates over :py:attr:`buf`
        :rtype: :py:class:`generator` which returns int values
        """
        idx = 0
        while idx < self.data.len:
            yield self.data.buf[idx]
            idx += 1

    def __len__(self):
        return self.data.len

    def __bytes__(self):
        return uctypes.bytes_at(self.data.buf__, self.data.len)

    def __repr__(self):
        return 'i2c_msg(%d,%d,%r)' % (self.data.addr, self.data.flags, self.__bytes__())

    def __str__(self):
        s = self.__bytes__()
        # Throw away non-decodable bytes
        s = s.decode(errors="ignore")
        return s

    @staticmethod
    def read(address, length):
        """
        Prepares an i2c read transaction.

        :param address: Slave address.
        :type: address: int
        :param length: Number of bytes to read.
        :type: length: int
        :return: New :py:class:`i2c_msg` instance for read operation.
        :rtype: :py:class:`i2c_msg`
        """
        return i2c_msg(addr=address, flags=I2C_M_RD, length=length)

    @staticmethod
    def write(address, buf):
        """
        Prepares an i2c write transaction.

        :param address: Slave address.
        :type address: int
        :param buf: Bytes to write. Either list of values or str.
        :type buf: list
        :return: New :py:class:`i2c_msg` instance for write operation.
        :rtype: :py:class:`i2c_msg`
        """
        if type(buf) is str:
            buf = bytes(map(ord, buf))
        else:
            buf = bytes(buf)
        return i2c_msg(addr=address, flags=0, buf=buf)


class i2c_rdwr_ioctl_data():
    """
    As defined in ``i2c-dev.h``.
    """
    desc = {
        'msgs':   (uctypes.PTR   | 0, i2c_msg.desc),
        'msgs__':  uctypes.INT32 | 0,
        'nmsgs':  uctypes.UINT32 | 4
    }

    def __init__(self, msgs, nmsgs):
        self.mem = bytearray(uctypes.sizeof(self.desc))
        self.mv  = memoryview(self.mem)
        self.data = uctypes.struct(uctypes.addressof(self.mv), self.desc, uctypes.NATIVE)

        self.child = msgs
        self.buf = memoryview(self.child)

        self.data.msgs__ = uctypes.addressof(self.buf)
        self.data.nmsgs = nmsgs

    def addr(self):
        return uctypes.addressof(self.mv)

    @staticmethod
    def create(*i2c_msg_instances):
        """
        Factory method for creating a i2c_rdwr_ioctl_data struct that can
        be called with ``ioctl(fd, I2C_RDWR, data.addr())``.

        :param i2c_msg_instances: Up to 42 i2c_msg instances
        :rtype: i2c_rdwr_ioctl_data
        """
        n_msg = len(i2c_msg_instances)
        # copy each byte of the i2c_msg into single array of i2c_msg's
        msg_array = bytearray() # size = n_msg * uctypes.sizeof(i2c_msg.desc)
        for msg in i2c_msg_instances:
            msg_array.extend(msg.mem)

        return i2c_rdwr_ioctl_data(
            msgs=msg_array,
            nmsgs=n_msg
        )


#############################################################


class SMBus(object):

    def __init__(self, bus=None, force=False):
        """
        Initialize and (optionally) open an i2c bus connection.

        :param bus: i2c bus number (e.g. 0 or 1)
            or an absolute file path (e.g. `/dev/i2c-42`).
            If not given, a subsequent  call to ``open()`` is required.
        :type bus: int or str
        :param force: force using the slave address even when driver is
            already using it.
        :type force: boolean
        """
        self.fd = None
        self.funcs = I2cFunc(0)
        if bus is not None:
            self.open(bus)
        self.address = None
        self.force = force
        self._force_last = None
        self._pec = 0

    def __enter__(self):
        """Enter handler."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit handler."""
        self.close()

    def open(self, bus):
        """
        Open a given i2c bus.

        :param bus: i2c bus number (e.g. 0 or 1)
            or an absolute file path (e.g. '/dev/i2c-42').
        :type bus: int or str
        :raise TypeError: if type(bus) is not in (int, str)
        """
        if isinstance(bus, int):
            filepath = "/dev/i2c-{}".format(bus)
        elif isinstance(bus, str):
            filepath = bus
        else:
            raise TypeError("Unexpected type(bus)={}".format(type(bus)))

        self.fd = os.open(filepath, os.O_RDWR)
#        self.funcs = self._get_funcs()

    def close(self):
        """
        Close the i2c connection.
        """
        if self.fd:
            os.close(self.fd)
            self.fd = None
            self._pec = 0

    def _get_pec(self):
        return self._pec

    def enable_pec(self, enable=True):
        """
        Enable/Disable PEC (Packet Error Checking) - SMBus 1.1 and later

        :param enable:
        :type enable: Boolean
        """
        if not (self.funcs & I2cFunc.SMBUS_PEC):
            raise IOError('SMBUS_PEC is not a feature')
        self._pec = int(enable)
        ioctl(self.fd, I2C_PEC, self._pec)

    pec = property(_get_pec, enable_pec)  # Drop-in replacement for smbus member "pec"
    """Get and set SMBus PEC. 0 = disabled (default), 1 = enabled."""

    def _set_address(self, address, force=None):
        """
        Set i2c slave address to use for subsequent calls.

        :param address:
        :type address: int
        :param force:
        :type force: Boolean
        """
        force = force if force is not None else self.force
        if self.address != address or self._force_last != force:
            if force is True:
                ioctl(self.fd, I2C_SLAVE_FORCE, address)
            else:
                ioctl(self.fd, I2C_SLAVE, address)
            self.address = address
            self._force_last = force

#    def _get_funcs(self):
#        """
#        Returns a 32-bit value stating supported I2C functions.
#        :rtype: int
#        """
#        f = c_uint32()
#        ioctl(self.fd, I2C_FUNCS, f)
#        return f.value

    def write_quick(self, i2c_addr, force=None):
        """
        Perform quick transaction. Throws IOError if unsuccessful.
        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param force:
        :type force: Boolean
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=0, size=I2C_SMBUS_QUICK)
        ioctl(self.fd, I2C_SMBUS, msg.addr())

    def read_byte(self, i2c_addr, force=None):
        """
        Read a single byte from a device.

        :rtype: int
        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param force:
        :type force: Boolean
        :return: Read byte value
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_READ,
            command=0,
            size=I2C_SMBUS_BYTE
        )
        ioctl(self.fd, I2C_SMBUS, msg.addr())
        return msg.data.data[0].byte

    def write_byte(self, i2c_addr, value, force=None):
        """
        Write a single byte to a device.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param value: value to write
        :type value: int
        :param force:
        :type force: Boolean
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=value, size=I2C_SMBUS_BYTE
        )
        ioctl(self.fd, I2C_SMBUS, msg.addr())

    def read_byte_data(self, i2c_addr, register, force=None):
        """
        Read a single byte from a designated register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Register to read
        :type register: int
        :param force:
        :type force: Boolean
        :return: Read byte value
        :rtype: int
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_READ, command=register, size=I2C_SMBUS_BYTE_DATA
        )
        ioctl(self.fd, I2C_SMBUS, msg.addr())
        return msg.data.data[0].byte

    def write_byte_data(self, i2c_addr, register, value, force=None):
        """
        Write a byte to a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Register to write to
        :type register: int
        :param value: Byte value to transmit
        :type value: int
        :param force:
        :type force: Boolean
        :rtype: None
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=register, size=I2C_SMBUS_BYTE_DATA
        )
        msg.data.data[0].byte = value
        ioctl(self.fd, I2C_SMBUS, msg.addr())

    def read_word_data(self, i2c_addr, register, force=None):
        """
        Read a single word (2 bytes) from a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Register to read
        :type register: int
        :param force:
        :type force: Boolean
        :return: 2-byte word
        :rtype: int
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_READ, command=register, size=I2C_SMBUS_WORD_DATA
        )
        ioctl(self.fd, I2C_SMBUS, msg.addr())
        return msg.data.data[0].word

    def write_word_data(self, i2c_addr, register, value, force=None):
        """
        Write a single word (2 bytes) to a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Register to write to
        :type register: int
        :param value: Word value to transmit
        :type value: int
        :param force:
        :type force: Boolean
        :rtype: None
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=register, size=I2C_SMBUS_WORD_DATA
        )
        msg.data.data[0].word = value
        ioctl(self.fd, I2C_SMBUS, msg.addr())

    def process_call(self, i2c_addr, register, value, force=None):
        """
        Executes a SMBus Process Call, sending a 16-bit value and receiving a 16-bit response

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Register to read/write to
        :type register: int
        :param value: Word value to transmit
        :type value: int
        :param force:
        :type force: Boolean
        :rtype: int
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=register, size=I2C_SMBUS_PROC_CALL
        )
        msg.data.data[0].word = value
        ioctl(self.fd, I2C_SMBUS, msg)
        return msg.data.data[0].word

    def read_block_data(self, i2c_addr, register, force=None):
        """
        Read a block of up to 32-bytes from a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Start register
        :type register: int
        :param force:
        :type force: Boolean
        :return: List of bytes
        :rtype: list
        """
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_READ, command=register, size=I2C_SMBUS_BLOCK_DATA
        )
        ioctl(self.fd, I2C_SMBUS, msg.addr())
        length = msg.data.data[0].block[0]
        return msg.data.data[0].block[1:length + 1]

    def write_block_data(self, i2c_addr, register, data, force=None):
        """
        Write a block of byte data to a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Start register
        :type register: int
        :param data: List of bytes
        :type data: list
        :param force:
        :type force: Boolean
        :rtype: None
        """
        length = len(data)
        if length > I2C_SMBUS_BLOCK_MAX:
            raise ValueError("Data length cannot exceed %d bytes" % I2C_SMBUS_BLOCK_MAX)
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=register, size=I2C_SMBUS_BLOCK_DATA
        )
        msg.data.data[0].block[0] = length
        msg.data.data[0].block[1:length + 1] = data
        ioctl(self.fd, I2C_SMBUS, msg.addr())

    def block_process_call(self, i2c_addr, register, data, force=None):
        """
        Executes a SMBus Block Process Call, sending a variable-size data
        block and receiving another variable-size response

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Register to read/write to
        :type register: int
        :param data: List of bytes
        :type data: list
        :param force:
        :type force: Boolean
        :return: List of bytes
        :rtype: list
        """
        length = len(data)
        if length > I2C_SMBUS_BLOCK_MAX:
            raise ValueError("Data length cannot exceed %d bytes" % I2C_SMBUS_BLOCK_MAX)
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=register, size=I2C_SMBUS_BLOCK_PROC_CALL
        )
        msg.data.data[0].block[0] = length
        msg.data.data[0].block[1:length + 1] = data
        ioctl(self.fd, I2C_SMBUS, msg.addr())
        length = msg.data.data[0].block[0]
        return msg.data.data[0].block[1:length + 1]

    def read_i2c_block_data(self, i2c_addr, register, length, force=None):
        """
        Read a block of byte data from a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Start register
        :type register: int
        :param length: Desired block length
        :type length: int
        :param force:
        :type force: Boolean
        :return: List of bytes
        :rtype: list
        """
        if length > I2C_SMBUS_BLOCK_MAX:
            raise ValueError("Desired block length over %d bytes" % I2C_SMBUS_BLOCK_MAX)
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_READ, command=register, size=I2C_SMBUS_I2C_BLOCK_DATA
        )
        msg.data.data[0].byte = length
        ioctl(self.fd, I2C_SMBUS, msg.addr())
        return msg.data.data[0].block[1:length + 1]

    def write_i2c_block_data(self, i2c_addr, register, data, force=None):
        """
        Write a block of byte data to a given register.

        :param i2c_addr: i2c address
        :type i2c_addr: int
        :param register: Start register
        :type register: int
        :param data: List of bytes
        :type data: list
        :param force:
        :type force: Boolean
        :rtype: None
        """
        length = len(data)
        if length > I2C_SMBUS_BLOCK_MAX:
            raise ValueError("Data length cannot exceed %d bytes" % I2C_SMBUS_BLOCK_MAX)
        self._set_address(i2c_addr, force=force)
        msg = i2c_smbus_ioctl_data.create(
            read_write=I2C_SMBUS_WRITE, command=register, size=I2C_SMBUS_I2C_BLOCK_DATA
        )
        msg.data.data[0].block[0] = length
        msg.data.data[0].block[1:length + 1] = data
        ioctl(self.fd, I2C_SMBUS, msg.addr())

    def i2c_rdwr(self, *i2c_msgs):
        """
        Combine a series of i2c read and write operations in a single
        transaction (with repeated start bits but no stop bits in between).

        This method takes i2c_msg instances as input, which must be created
        first with :py:meth:`i2c_msg.read` or :py:meth:`i2c_msg.write`.

        :param i2c_msgs: One or more i2c_msg class instances.
        :type i2c_msgs: i2c_msg
        :rtype: None
        """
        ioctl_data = i2c_rdwr_ioctl_data.create(*i2c_msgs)
        ioctl(self.fd, I2C_RDWR, ioctl_data.addr())


    ### ----> COMPATIBILITY WITH machine.i2c <---- ###
    def scan(self, force=False):
        devices = []
        for addr in range(0x03, 0x77 + 1):
            read = SMBus.read_byte, (addr,), {'force':force}
            write = SMBus.write_byte, (addr, 0), {'force':force}

            for func, args, kwargs in (read, write):
                try:
                    data = func(self, *args, **kwargs)
                    devices.append(addr)
                    break
                except OSError as expt:
                    if expt.errno == 16:
                        # just busy, maybe permanent by a kernel driver or just temporary by some user code
                        pass

        return devices

    def readfrom_mem_into(self, i2c_addr, register, mv):
        mv[:] = self.read_i2c_block_data(i2c_addr, register, len(mv))

    def writeto_mem(self, i2c_addr, register, mv):
        self.write_i2c_block_data(i2c_addr, register, mv)

