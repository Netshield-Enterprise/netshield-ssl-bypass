"""
Unit tests for APK Analyzer module
"""

import unittest
import os
from unittest.mock import Mock, patch, MagicMock
from apk_analyzer import SSLPinningDetector


class TestSSLPinningDetector(unittest.TestCase):
    
    def setUp(self):
        """Set up test configuration"""
        self.config = {
            'apk': {
                'apktool_path': 'apktool',
                'output_dir': './test_output',
                'cleanup_after_analysis': False
            }
        }
        self.detector = SSLPinningDetector(self.config)
    
    def test_detector_initialization(self):
        """Test detector initializes correctly"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.apktool_path, 'apktool')
    
    def test_pattern_detection_okhttp(self):
        """Test OkHttp pattern detection"""
        patterns = self.detector.PATTERNS['okhttp']
        self.assertIn('okhttp3.CertificatePinner', patterns[0])
    
    def test_pattern_detection_flutter(self):
        """Test Flutter pattern detection"""
        patterns = self.detector.PATTERNS['flutter']
        self.assertTrue(any('libflutter.so' in p for p in patterns))
    
    @patch('subprocess.run')
    def test_get_package_name(self, mock_run):
        """Test package name extraction"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="package: name='com.example.app' versionCode='1'"
        )
        
        package_name = self.detector._get_package_name('/fake/path.apk')
        self.assertEqual(package_name, 'com.example.app')
    
    def test_generate_recommendations_no_pinning(self):
        """Test recommendations when no pinning detected"""
        results = {
            'pinning_detected': False,
            'pinning_types': []
        }
        
        recommendations = self.detector._generate_recommendations(results)
        self.assertEqual(len(recommendations), 1)
        self.assertIn('No SSL pinning detected', recommendations[0])
    
    def test_generate_recommendations_flutter(self):
        """Test recommendations for Flutter app"""
        results = {
            'pinning_detected': True,
            'pinning_types': ['flutter']
        }
        
        recommendations = self.detector._generate_recommendations(results)
        self.assertTrue(any('flutter_bypass.js' in r for r in recommendations))
    
    def test_generate_recommendations_okhttp(self):
        """Test recommendations for OkHttp"""
        results = {
            'pinning_detected': True,
            'pinning_types': ['okhttp']
        }
        
        recommendations = self.detector._generate_recommendations(results)
        self.assertTrue(any('okhttp_bypass.js' in r for r in recommendations))


if __name__ == '__main__':
    unittest.main()
