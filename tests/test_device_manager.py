"""
Unit tests for Device Manager module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from device_manager import DeviceManager


class TestDeviceManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test configuration"""
        self.config = {
            'device': {
                'adb_path': 'adb',
                'root_required': True
            },
            'frida': {
                'server_path': '/data/local/tmp/frida-server',
                'default_port': 27042
            }
        }
        self.device_mgr = DeviceManager(self.config)
    
    def test_initialization(self):
        """Test device manager initializes correctly"""
        self.assertIsNotNone(self.device_mgr)
        self.assertEqual(self.device_mgr.adb_path, 'adb')
        self.assertIsNone(self.device_mgr.selected_device)
    
    @patch('subprocess.run')
    def test_check_adb_available_success(self, mock_run):
        """Test ADB availability check - success"""
        mock_run.return_value = Mock(returncode=0)
        
        result = self.device_mgr.check_adb_available()
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_check_adb_available_failure(self, mock_run):
        """Test ADB availability check - failure"""
        mock_run.side_effect = FileNotFoundError()
        
        result = self.device_mgr.check_adb_available()
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_list_devices(self, mock_run):
        """Test device listing"""
        mock_run.return_value = Mock(
            stdout="List of devices attached\nemulator-5554\tdevice\n"
        )
        
        devices = self.device_mgr.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['id'], 'emulator-5554')
        self.assertEqual(devices[0]['status'], 'device')
    
    @patch('subprocess.run')
    def test_select_device_auto(self, mock_run):
        """Test auto device selection"""
        mock_run.return_value = Mock(
            stdout="List of devices attached\nemulator-5554\tdevice\n"
        )
        
        result = self.device_mgr.select_device()
        self.assertTrue(result)
        self.assertEqual(self.device_mgr.selected_device, 'emulator-5554')
    
    @patch('subprocess.run')
    def test_check_root_access_success(self, mock_run):
        """Test root access check - success"""
        self.device_mgr.selected_device = 'emulator-5554'
        mock_run.return_value = Mock(
            returncode=0,
            stdout="uid=0(root) gid=0(root)"
        )
        
        result = self.device_mgr.check_root_access()
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_check_root_access_failure(self, mock_run):
        """Test root access check - failure"""
        self.device_mgr.selected_device = 'emulator-5554'
        mock_run.return_value = Mock(
            returncode=1,
            stdout=""
        )
        
        result = self.device_mgr.check_root_access()
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
