import aexpect
import logging
import os
import ast
import subprocess
import json
import time
import socket
import errno

from virttest import virt_vm
from virttest import remote
from virttest import utils_misc
from virttest import utils_net

class QMPError(Exception):
    """QMP base exception"""


class QMPConnectError(QMPError):
    """QMP connection exception"""


class QMPCapabilitiesError(QMPError):
    """QMP negotiate capabilities exception"""


class QMPTimeoutError(QMPError):
    """QMP timeout exception"""


class VMLifeError(Exception):
    """Vmlife error exception"""
    pass


class VM(virt_vm.BaseVM):
    '''
    this is basic stratovirt vm and vm operations for stratovirt vm
    '''

    def __init__(self, name, params, root_dir, address_cache, state=None):
        '''
        Initialize stratovirt VM object with several params

        :param name: The name of the stratovirt VM
        :param params: Directory of related parameters for a custum stratovirt VM
        :param root_dir: base directory of related files
        :param address_cache: A dict that maps MAC addresses to IP addresses
        :param state: If provided, use this as self.__dict__
        '''
        super(VM, self).__init__(name, params)
        self.root_dir = root_dir
        self.address_cache = address_cache

        self.qmp_socket = None
        self.process = None
        self.__qmp = None
        self.__qmp_set = True

        self._console_address = self.params.get("console_sock")
        self._console_set = True
        self._events = []
        self._launched = False
        self._machine = self.params.get("machine")
        self._monitor_address = self.params.get("mon_sock")
        self._name = name
        self._remove_files = list()
        self._vm_monitor = None
        self.bin_path = self.params.get("stratovirt_binary")
        self.daemon = self.params.get("daemon")
        self.guest_ip = None
        self.guest_ips = list()
        self.interfaces = []
        self.ipalloc_type = self.params.get("ipalloc")
        self.logpath = self.params.get("logpath")
        self.mem_share = self.params.get("mem_share")
        self.mon_sock = self.params.get("mon_sock")
        self.pid = None
        self.pidfile = None
        self._sock_dir = self.root_dir
        self.seccomp = True
        self.serial_session = None
        self.taps = list()
        self.vnetnums = int(self.params.get("vnetnums"))
        self.vmid = self.params.get("uuid")
        self.vmtype = self.params.get("vm_type")
        self.remote_sessions = []
        self.full_command = None

    def make_create_command(self, name=None, params=None, root_dir=None):
        '''
        Generating command line to spawn a new stratovirt VM.
        Params are optional. If not provided, correspoding values that stored in class
        will be used.

        :param name: name of the object
        :param params: dictionary that contains VM params
        :param root_dir: directory for relative files
        :return: a new stratovirt VM

        e.g.:
        root_dir:
        "stratovirt": "/home/stratovirt"
        "kernel": "/home/image/vmlinux.bin"
        "drive": "file=/home/image/stratovirt-dfx-rootfs.ext4,id=rootfs,readonly=off"
        "mem-path": "/home/mem"

        params:
        "machine": "type=MicroVm,dump-guest-core=off,mem-share=off"

        '''

        def kernel(path):
            '''
            :param path: for now only kernal path
            :return: a part of string of commandline
            '''
            return "-kernel " + path

        def append(dic):
            '''
            :param dic: additional key-value pairs for stratovirt VM
            :return: a part of string of commandline
            '''
            dic = ast.literal_eval(dic)
            return "-append " + " ".join([key + '=' + dic[key] for key in dic]) + " rw "

        def drive(dic):
            '''
            :param dic: key-value pairs for driver
            :return: a part of string of commandline
            '''
            dic = ast.literal_eval(dic)
            return "-drive " + ",".join([key + '=' + dic[key] for key in dic])

        def api_channel(path):
            '''
            :param dic: currently path value for api-channel
            :return: a part of string of commandline
            '''
            return "-api-channel " + "unix:%s" % path

        def console_sock(path):
            '''
            :param dic: currently path value for api-channel
            :return: a part of string of commandline
            '''
            return "-chardev " + "id=console_0,path=%s" % path  

        def netdev_init(dic):
            '''
            :param dic: currently the value for -netdev, type dict
            :return: a part of string of commandline
            '''
            if not isinstance(dic, dict):
                dic = ast.literal_eval(dic)
            if self.virtnet[0] and self.virtnet[0]["mac"]:
                dic["mac"] = self.virtnet[0]["mac"]
            return "-netdev " + ",".join([key + '=' + dic[key] for key in dic])


        def serial(value):
            '''
            :param value: currently the value for serial
            :return: a part of string of commandline
            '''
            return "-serial "+value

        def mem(value):
            '''
            :param value: currently the value for memory
            :return: a part of string of commandline
            '''
            return "-m " + value

        def smp(value):
            '''
            :param value: currently the value for smp
            :return: a part of string of commandline
            '''
            return "-smp " + value

        def mem_path(path):
            '''
            :param value: currently the path for memory path
            :return: a part of string of commandline
            '''
            return "-mem-path " + path

        def machine(dic):
            '''
            :param dic: key-value pairs for stratovirt VM info
            :return: a part of string of commandline
            '''
            dic = ast.literal_eval(dic)
            return "-machine " + ",".join([key + '=' + dic[key] for key in dic])
       
        def iothreads(list):
            '''
            :param value: currently the value for -iothreads, type list
            :return: a part of string of commandline
            '''
            return "-iothread id=" + " -iothread id=".join([value for value in list])

        def add_drive(list):
            '''
            :param value: the value specified when configuring more -drive, type list
            :return: a part of string of commandline
            '''
            drive_cmd = ""
            for drive_dic in list:
                if not isinstance(drive_dic, dict):
                    drive_dic = ast.literal_eval(drive_dic)
                drive_cmd += "-drive " + ','.join([key + '=' + drive_dic[key] for key in drive_dic])
            return drive_cmd

        def add_net(list):
            '''
            :param value: the value specified when configuring more -netdev, type list
            :return: a part of string of commandline
            '''
            netdev_cmd = ""
            for netdev_dic in list:
                if not isinstance(netdev_dic, dict):
                    netdev_dic = ast.literal_eval(netdev_dic)
                netdev_cmd += "-netdev " + ','.join([key + '=' + netdev_dic[key] for key in netdev_dic])
            return netdev_cmd
				
        if not name and not params and not root_dir and self.devices:
            return self.devices

        if not name:
            name = self.name
        if not params:
            params = self.params
        if not root_dir:
            root_dir = self.root_dir

        for nic in self.virtnet:
            nic_params = params.object_params(nic.nic_name)
            self.add_nic(**dict(nic))

        cmd = ""
        if 'stratovirt' not in root_dir:
            cmd += params.get("stratovirt_binary")
        else:
            cmd += root_dir['stratovirt']
            del root_dir['stratovirt']

        for key in params:
            try:
                if key == "iothreads":
                    cmd += " " + eval(key.replace("-","_") + '(params.get_list(key))')
                else:
                    cmd += " " + eval(key.replace("-","_") + '(params[key])')
            except:
                pass

        logging.info(cmd)
        return cmd

    def get_pid(self):
        """Get pid from ps"""

        _cmd = "ps -ef | grep %s | grep -v grep | grep -v ps | " \
               "awk '{print $2}' | head -1" % self.bin_path
        logging.info("_cmd: %s" % _cmd)
        output = subprocess.getoutput(_cmd)
        logging.debug("get output %s" % output.strip())
        return int(output.strip())

    def get_pid_from_file(self):
        """Get pid from file"""
        if self.pidfile is not None:
            with open(self.pidfile, 'r') as pidf:
                return int(pidf.read())

        return None

    def qmp_reconnect(self):
        """Reconnect qmp when sock is dead"""
        if self.__qmp:
            self.close_sock()

        if isinstance(self.mon_sock, tuple):
            self.qmp_monitor_protocol(self.mon_sock)
        else:
            self.qmp_monitor_protocol(self._vm_monitor)
        if self.__qmp:
            self.connect()

    def _pre_shutdown(self):
        pass

    def shutdown(self, has_quit=False):
        """Terminate the VM and clean up"""
        if not self._launched:
            return

        self._pre_shutdown()
        if self.daemon or self.is_running():
            if self.__qmp:
                try:
                    if not has_quit:
                        self.qmp_cmd('quit')
                        self.event_wait(name='SHUTDOWN', timeout=10,
                                        match={'data': {'guest': False, 'reason': 'host-qmp-quit'}})
                except Exception:
                    logging.error('match failed!')
                    self.process.close()
            else:
                self.process.close()
        if not self.daemon:
            self.process.get_status()
        else:
            self.wait_pid_exit()
        self._post_shutdown()
        self._launched = False

    def destroy(self, signal=9):
        """Destroy the vm by send signal"""
        if not self._launched:
            return

        self._pre_shutdown()
        subprocess.run("kill -%d %s" % (signal, self.pid), shell=True, check=True)
        self._post_shutdown()
        self._launched = False

    def inshutdown(self):
        """Terminate the vm from inner"""
        if not self._launched:
            return

        self._pre_shutdown()
        if self.daemon or self.is_running():
            if self.serial_session:
                try:
                    self.serial_session.run_func("cmd_output", "reboot")
                    self.event_wait(name='SHUTDOWN')
                except Exception:
                    pass
            else:
                return
        if not self.daemon:
            self.process.get_status()
        else:
            self.wait_pid_exit()
        self._post_shutdown()
        self._launched = False

    def _post_shutdown(self):
        """Post shutdown"""
        exitcode = self.exitcode()
        if exitcode is not None and exitcode < 0:
            msg = 'stratovirt received signal %i: %s'
            if self.full_command:
                command = ' '.join(self.full_command)
            else:
                command = ''
            logging.warning(msg, exitcode, command)

        if self.__qmp:
            self.close_sock()

        if self.serial_session:
            self.serial_session.close()

        if self.console_manager:
            self.console_manager.close()
        
        if self.process:
            self.process.close()

        for _file in self._remove_files:
            try:
                os.remove(_file)
            except OSError as exception:
                if exception.errno == errno.ENOENT:
                    return
                raise

        if self.withpid:
            subprocess.run("rm -rf %s" % self.pidfile, shell=True, check=True)

    def _pre_launch(self):
        if self.__qmp_set:
            if self._monitor_address is not None:
                self._vm_monitor = self._monitor_address
                if not isinstance(self._vm_monitor, tuple):
                    self._remove_files.append(self._vm_monitor)
            else:
                self._vm_monitor = os.path.join(self._sock_dir,
                                                self._name + "_" + self.vmid + ".sock")
                self._remove_files.append(self._vm_monitor)

        if os.path.exists(self.mon_sock):
            os.remove(self.mon_sock)

        if os.path.exists(self._console_address):
            os.remove(self._console_address)

    def _create_serial_console(self):
        self._wait_console_create()
        output_func = utils_misc.log_line# Because qemu-kvm uses this
        # Because qemu-kvm hard-codes this
        self.serial_console = aexpect.ShellSession(
            "/usr/bin/nc -U %s" % self._console_address,
            auto_close=False,
            output_func=output_func,
            prompt=r"[\#\$]",
            status_test_command="echo $?"
        )

    def scp_file(self, local_file, dest_file):
        """
        Send file to guest

        Args:
            local_file: local file in host
            dest_file: dest file in guest
        """
        remote.scp_to_remote(self.guest_ip, 22, self.params.get("vm_username"),
                             self.params.get("vm_password"), local_file, dest_file,
                             timeout=60.0)

    def launch(self):
        """Start a vm and establish a qmp connection"""
        self._pre_launch()
        self.full_command = (self.make_create_command(params=self.params))
        logging.info("Running stratovirt command (reformatted): %s" % self.full_command)
        self.process = aexpect.run_tail(
                self.full_command, None,
                logging.info, "[stratovirt output] ",
                auto_close=False)

        logging.info("Created stratovirt process with parent PID %d", self.process.get_pid())
        self.pid = self.process.get_pid()
        if not self.params.get_boolean("error_test", False):
            # Make sure stratovirt is not defunct
            if self.process.is_defunct():
                logging.error("Bad things happened, stratovirt process is defunct")
                err = ("stratovirt is defunct.\nstratovirt output:\n%s"
                       % self.process.get_output())
                self.destroy()
                raise virt_vm.VMStartError(self.name, err)

            # Make sure the process was started successfully
            if not self.process.is_alive():
                status = self.process.get_status()
                output = self.process.get_output().strip()
                e = virt_vm.VMCreateError(self.full_command, status, output)
                self.destroy()
                raise e

            logging.info("_post_launch start")
            self._post_launch()

    def post_launch_serial(self):
        """Create a serial and wait for active"""
        if self._console_set:
            self.create_serial_console()
            self.serial_session = self.wait_for_serial_login(timeout=60, internal_timeout=10,
                                                             username=self.params.get("vm_username"),
                                                             password=self.params.get("vm_password"))
        else:
            time.sleep(2)

    def post_launch_qmp(self):
        """Set a QMPMonitorProtocol"""
        if isinstance(self.mon_sock, tuple):
            self.qmp_monitor_protocol(self.mon_sock)
        else:
            self.qmp_monitor_protocol(self._vm_monitor)
        if self.__qmp:
            self.connect()

    def post_launch_vnet(self):
        """Nothing is needed at present"""
        pass

    def _post_launch(self):
        self._launched = True
        logging.info("_post_launch prepare")
        self.post_launch_serial()
        if self.vnetnums > 0:
            self.post_launch_vnet()
            self.config_network()

    def _wait_console_create(self):
        os.stat(self._console_address)

    def wait_pid_exit(self):
        """Wait vm pid when vm exit"""
        logging.debug("===== check pid %s exit" % self.pid)
        time.sleep(2)
        if os.path.exists("/proc/%d" % self.pid):
            raise VMLifeError("check pid exit failed, vm shutdown/destroy failed!")

    def config_network(self, model='dhcp', index=0):
        """Config vm network"""
        self.interfaces = self.get_interfaces_inner()

        tapname = self.params.get("netdev")

        utils_net.add_to_bridge(tapname, self.params.get("netdst"))
        subprocess.run("ifconfig %s up" % tapname, shell=True, check=True)
        if 'stratovirt' in self.vmtype:
            self.serial_session.cmd_output('systemctl stop NetworkManager')
            self.serial_session.cmd_output('systemctl stop firewalld')
            # enable ssh login
            _cmd = "sed -i \"s/^PermitRootLogin.*/PermitRootLogin yes/g\" /etc/ssh/sshd_config"
            self.serial_session.cmd_status_output(_cmd, internal_timeout=2)
            self.serial_session.cmd_status_output("systemctl restart sshd", internal_timeout=2)
        if 'dhcp' in model:
            self.serial_session.cmd_output("dhclient %s" % self.interfaces[index])
            ip_cmd = "ip a | awk '/inet/ {print $2}' | cut -f2 -d ':' | " \
                     "awk -F / '{print $1}' | awk NF |tail -n 1"

            output = self.serial_session.cmd_output(ip_cmd)
            self.guest_ips.append(output)
            if index == 0:
                self.guest_ip = output

        logging.debug("==== check ip addr info in Guest ======\n %s" %
                  self.serial_session.cmd_output("ip addr"))


    def kill(self):
        """Kill VM"""
        try:
            self.shutdown()
        except Exception as err:
            logging.warning("got exception %s, try to destroy vm" % err)
            self.destroy()

    def is_running(self):
        """Returns true if the VM is running."""
        return not self.is_dead() and self.query_status()["return"]["status"] == "running"

    def is_alive(self):
        """Returns true if the VM is running."""
        return not self.is_dead()

    def is_dead(self):
        """
        Return True if the stratovirt process is dead.
        """
        return not self.process or not self.process.is_alive()

    def is_paused(self):
        """
        Return True if the stratovirt process is paused ('stop'ed)
        """
        if self.is_dead():
            return False
        return self.query_status()["return"]["status"] == "paused"

    def exitcode(self):
        """Returns the exit code if possible, or None."""
        if self.process is None:
            return None
        return self.process.get_status()

    def enable_qmp_set(self):
        """
        Enable qmp monitor
        set in preparation phase
        """
        self.__qmp_set = True

    def disable_qmp_set(self):
        """
        Disable qmp monitor
        set in preparation phase
        """
        self.__qmp = None
        self.__qmp_set = False

    def qmp_command(self, cmd, **args):
        """Run qmp command"""
        qmp_dict = dict()
        for key, value in args.items():
            if key.find("_") != -1:
                qmp_dict[key.replace('_', '-')] = value
            else:
                qmp_dict[key] = value

        rep = self.qmp_cmd(cmd, args=qmp_dict)
        if rep is None:
            raise QMPError("Monitor was closed")

        return rep

    def qmp_event_acquire(self, wait=False, return_list=False):
        """
        Get qmp event or events.

        Args:
            return_list: if return_list is True, then return qmp
            events. Else, return a qmp event.
        """
        if not return_list:
            if not self._events:
                return self.get_events(wait=wait, only_event=True)
            return self._events.pop(0)
        event_list = self.get_events(wait=wait)
        event_list.extend(self._events)
        self._events.clear()
        self.clear_events()
        return event_list

    def event_wait(self, name, timeout=60.0, match=None):
        """
        Wait for an qmp event to match exception event.

        Args:
            match: qmp match event, such as
            {'data':{'guest':False,'reason':'host-qmp-quit'}}
        """
        while True:
            event = self.get_events(wait=timeout, only_event=True)
            try:
                if event['event'] == name:
                    for key in match:
                        if key in event and match[key] == event[key]:
                            return event
            except TypeError:
                if event['event'] == name:
                    return event
            self._events.append(event)

    def add_env(self, key, value):
        """Add key, value to self.env"""
        self.env[key] = value

    def add_drive(self, **kwargs):
        """Add drive"""
        drivetemp = dict()
        drivetemp["drive_id"] = kwargs.get("drive_id", utils.generate_random_name())
        drivetemp["path_on_host"] = kwargs.get('path_on_host', None)
        drivetemp["read_only"] = kwargs.get("read_only", "true")
        if "drive" in self.configdict:
            self.configdict["drive"].append(drivetemp)
        else:
            self.configdict["drive"] = [drivetemp]

    def console_enable(self):
        """Set console"""
        self._console_set = True

    def console_disable(self):
        """Unset console"""
        self._console_set = False

    def set_device_type(self, device_type):
        """Set device type"""
        self._console_device_type = device_type

    def set_console_device_index(self, console_device_index):
        """Set console device index"""
        if not console_device_index:
            console_device_index = 0
        self._console_device_index = console_device_index

    def get_interfaces_inner(self):
        """Get interfaces list from guest inner"""
        cmd = "cat /proc/net/dev"
        status, output = self.serial_session.cmd_status_output(cmd, internal_timeout=2)
        interfaces = []
        if status != 0:
            return interfaces
        for line in output.splitlines():
            temp = line.split(":")
            if len(temp) != 2:
                continue
            if "lo" not in temp[0] and "virbr0" not in temp[0]:
                interfaces.append(temp[0].strip())

        interfaces.sort()
        return interfaces

    def get_guest_hwinfo(self):
        """
        Get guest hwinfo via serial_session

        Returns:
            {"cpu": {"vcpu_count": xx, "maxvcpu": xx},
            "mem": {"memsize": xx, "maxmem": xx},
            "virtio": {"virtio_blk": [{"name": "virtio0"}],
                    "virtio_console": [{"name": "virtio1"}],
                    "virtio_net": [{"name": "virtio2"}],
                    "virtio_rng": [{"name": "virtio3"}],
                    }
            }
        """
        retdict = {"cpu": {}, "mem": {}, "virtio": {}}
        if self.serial_session is not None:
            vcpu_count = int(self.serial_session.cmd_output("grep -c processor /proc/cpuinfo"))
            memsize = int(self.serial_session.cmd_output("grep MemTotal /proc/meminfo | awk '{print $2}'"))
            retdict["cpu"] = {"vcpu_count": vcpu_count, "maxvcpu": vcpu_count}
            retdict["mem"] = {"memsize": memsize, "maxmem": memsize}
            # ignore virtio_rng device now
            for dev in ["virtio_blk", "virtio_net", "virtio_console"]:
                devdir = "/sys/bus/virtio/drivers/%s" % dev
                _cmd = "test -d %s && ls %s | grep virtio" % (devdir, devdir)
                virtiodevs = self.serial_session.cmd_output(_cmd).strip().split()
                for virtiodev in virtiodevs:
                    _tempdev = {"name": virtiodev}
                    if dev not in retdict["virtio"]:
                        retdict["virtio"][dev] = list()
                    retdict["virtio"][dev].append(_tempdev)

        return retdict

    def get_lsblk_info(self):
        """
        Get lsblk info via serial_session

        Returns:
            {
                "vdx": {"size": xx, "readonly": xx},
            }
        """
        retdict = {}
        if self.serial_session is not None:
            _output = self.serial_session.cmd_output("lsblk")
            for line in _output.split("\n"):
                temp = line.split()
                if len(temp) == 6:
                    name = temp[0]
                    size = temp[3]
                    readonly = temp[4]
                    if name not in retdict:
                        retdict[name] = {"size": size, "readonly": readonly}

        return retdict

    def stop(self):
        """Pause all vcpu"""
        return self.qmp_command("stop")

    def cont(self):
        """Resume paused vcpu"""
        return self.qmp_command("cont")

    def quit(self):
        """Quit the vm"""
        return self.qmp_command("quit")

    def device_add(self, **kwargs):
        """Hotplug device"""
        return self.qmp_command("device_add", **kwargs)

    def device_del(self, **kwargs):
        """Unhotplug device"""
        return self.qmp_command("device_del", **kwargs)

    def netdev_add(self, **kwargs):
        """Hotplug a netdev"""
        return self.qmp_command("netdev_add", **kwargs)

    def netdev_del(self, **kwargs):
        """Unhotplug a netdev"""
        return self.qmp_command("netdev_del", **kwargs)

    def add_disk(self, diskpath, index=1, check=True):
        """Hotplug a disk to vm"""
        logging.debug("hotplug disk %s to vm" % diskpath)
        devid = "drive-%d" % index
        resp = self.qmp_command("blockdev-add", node_name="drive-%d" % index,
                                file={"driver": "file", "filename": diskpath})
        logging.debug("blockdev-add return %s" % resp)
        if check:
            assert "error" not in resp
        resp = self.device_add(id=devid, driver="virtio-blk-mmio", addr=str(hex(index)))
        logging.debug("device_add return %s" % resp)
        if check:
            assert "error" not in resp

        return resp

    def del_disk(self, index=1, check=True):
        """Unplug a disk"""
        logging.debug("unplug diskid %d to vm" % index)
        devid = "drive-%d" % index
        resp = self.device_del(id=devid)
        if check:
            assert "error" not in resp

    def add_net(self, net_dict=None, index=None):
        """Hotplug a net device"""
        if not isinstance(net_dict, dict):
            raise Exception("the hotplug netdev info")

        resp = self.netdev_add(id=net_dict["id"], ifname=net_dict["netdev"])
        assert "error" not in resp
        logging.debug("netdev_add return %s" % resp)

        resp = self.device_add(id=net_dict["id"], driver="virtio-net-mmio", addr="0x%s" % index)
        assert "error" not in resp
        logging.debug("device_add return %s" % resp)

        if index == 0:
            self.config_network(index=index, model="dhcp")

        return resp

    def del_net(self, net_dict=None):
        """Del net"""
        if not isinstance(net_dict, dict):
            raise Exception("the hotplug netdev info")

        resp = self.device_del(id=net_dict["id"])
        assert "error" not in resp
        logging.debug("device_del return %s", resp)

    def query_hotpluggable_cpus(self):
        """Query hotpluggable cpus"""
        return self.qmp_command("query-hotpluggable-cpus")

    def query_cpus(self):
        """Query cpus"""
        return self.qmp_command("query-cpus")

    def query_status(self):
        """Query status"""
        return self.qmp_command("query-status")

    def query_balloon(self):
        """Query balloon size"""
        return self.qmp_command("query-balloon")

    def balloon_set(self, **kwargs):
        """Set balloon size"""
        return self.qmp_command("balloon", **kwargs)

    def qmp_monitor_protocol(self, address):
        """Set QMPMonitorProtocol"""
        self.__qmp = {'events': [],
                      'address': address,
                      'sock': socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                      }

    def __sock_recv(self, only_event=False):
        """Get data from socket"""
        recv = self.__qmp['sock'].recv(1024).decode('utf-8').split('\n')
        if recv and not recv[-1]:
            recv.pop()
        resp = None
        while recv:
            resp = json.loads(recv.pop(0))
            if 'event' not in resp:
                return resp
            logging.debug("-> %s", resp)
            self.__qmp['events'].append(resp)
            if only_event:
                return resp
        return resp

    def get_events(self, wait=False, only_event=False):
        """
        Get new events or event from socket.
        Push them to __qmp['events']

        Args:
            wait (bool): block until an event is available.
            wait (float): If wait is a float, treat it as a timeout value.

        Raises:
            QMPTimeoutError: If a timeout float is provided and the timeout
            period elapses.
            QMPConnectError: If wait is True but no events could be retrieved
            or if some other error occurred.
        """

        # Wait for new events, if needed.
        # if wait is 0.0, this means "no wait" and is also implicitly false.
        if not self.__qmp['events'] and wait:
            if isinstance(wait, float):
                self.__qmp['sock'].settimeout(wait)
            try:
                ret = self.__sock_recv(only_event=True)
            except socket.timeout:
                raise QMPTimeoutError("Timeout waiting for event")
            except:
                raise QMPConnectError("Error while receiving from socket")
            if ret is None:
                raise QMPConnectError("Error while receiving from socket")
            self.__qmp['sock'].settimeout(None)

        if self.__qmp['events']:
            if only_event:
                return self.__qmp['events'].pop(0)
            return self.__qmp['events']
        return None

    def connect(self):
        """
        Connect to the QMP Monitor and perform capabilities negotiation.

        Returns:
            QMP greeting if negotiate is true
            None if negotiate is false

        Raises:
            QMPConnectError if the greeting is not received or QMP not in greetiong
            QMPCapabilitiesError if fails to negotiate capabilities
        """
        self.__qmp['sock'].connect(self.__qmp['address'])
        greeting = self.__sock_recv()
        if greeting is None or "QMP" not in greeting:
            raise QMPConnectError
        # Greeting seems ok, negotiate capabilities
        resp = self.qmp_cmd('qmp_capabilities')
        logging.info("resp is %s" % resp)
        if resp and "return" in resp:
            return greeting
        raise QMPCapabilitiesError

    def qmp_cmd(self, name, args=None, cmd_id=None):
        """
        Build a QMP command and send it to the monitor.

        Args:
            name: command name
            args: command arguments
            cmd_id: command id
        """
        qmp_cmd = {'execute': name}
        if args:
            qmp_cmd['arguments'] = args
        if cmd_id:
            qmp_cmd['id'] = cmd_id

        logging.debug("<- %s", qmp_cmd)
        logging.debug("self.__qmp is %s", self.__qmp)
        try:
            self.__qmp['sock'].sendall(json.dumps(qmp_cmd).encode('utf-8'))
        except OSError as err:
            if err.errno == errno.EPIPE:
                return None
            raise err
        resp = self.__sock_recv()
        logging.debug("-> %s", resp)
        return resp

    def error_cmd(self, cmd, **kwds):
        """Build and send a QMP command to the monitor, report errors if any"""
        ret = self.qmp_cmd(cmd, kwds)
        if "error" in ret:
            raise Exception(ret['error']['desc'])
        return ret['return']

    def clear_events(self):
        """Clear current list of pending events."""
        self.__qmp['events'] = []

    def close_sock(self):
        """Close the socket and socket file."""
        if self.__qmp['sock']:
            self.__qmp['sock'].close()
            self.__qmp = None

    def settimeout(self, timeout):
        """Set the socket timeout."""
        self.__qmp['sock'].settimeout(timeout)

    def is_af_unix(self):
        """Check if the socket family is AF_UNIX."""
        return socket.AF_UNIX == self.__qmp['sock'].family

    def cleanup_serial_console(self):
        """
        Close serial console and associated log file
        """
        if self.serial_console is not None:
            self.serial_console.close()
            self.serial_console = None
            self.serial_console_log = None
            self.console_manager.set_console(None)
        if hasattr(self, "migration_file"):
            try:
                os.unlink(self.migration_file)
            except OSError:
                pass

    def add_nic(self, **params):
        """
        Add new or setup existing NIC, optionally creating netdev if None

        :param params: Parameters to set
        :param nic_name: Name for existing or new device
        :param nic_model: Model name to emulate
        :param netdev_id: Existing net device ID name, None to create new
        :param mac: Optional MAC address, None to randomly generate.
        """
        # returns existing or new nic object
        nic = super(VM, self).add_nic(**params)
        nic_index = self.virtnet.nic_name_index(nic.nic_name)
        nic.set_if_none('vlan', str(nic_index))
        nic.set_if_none('device_id', utils_misc.generate_random_id())
        nic.set_if_none('queues', '1')
        if 'netdev_id' not in nic:
            # virtnet items are lists that act like dicts
            nic.netdev_id = self.add_netdev(**dict(nic))
        nic.set_if_none('nic_model', params['nic_model'])
        nic.set_if_none('queues', params.get('queues', '1'))
        if params.get("enable_msix_vectors") == "yes" and int(nic.queues) > 1:
            nic.set_if_none('vectors', 2 * int(nic.queues) + 2)
        return nic

    def add_netdev(self, **params):
        """
        Hotplug a netdev device.

        :param params: NIC info. dict.
        :return: netdev_id
        """
        nic_name = params['nic_name']
        nic = self.virtnet[nic_name]
        nic_index = self.virtnet.nic_name_index(nic_name)
        nic.set_if_none('netdev_id', utils_misc.generate_random_id())
        nic.set_if_none('ifname', self.virtnet.generate_ifname(nic_index))
        nic.set_if_none('netdev_extra_params',
                        params.get('netdev_extra_params'))
        nic.set_if_none('nettype', 'bridge')
        if nic.nettype in ['bridge', 'macvtap']:  # implies tap
            # destination is required, hard-code reasonable default if unset
            # nic.set_if_none('netdst', 'virbr0')
            # tapfd allocated/set in activate because requires system resources
            nic.set_if_none('queues', '1')
            ids = []
            for i in range(int(nic.queues)):
                ids.append(utils_misc.generate_random_id())
            nic.set_if_none('tapfd_ids', ids)

        elif nic.nettype == 'user':
            pass  # nothing to do
        else:  # unsupported nettype
            raise virt_vm.VMUnknownNetTypeError(self.name, nic_name,
                                                nic.nettype)
        return nic.netdev_id
