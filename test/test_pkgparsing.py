'''
Provides tests for parsing functionality for various package managers.
'''

from analyzer.system.centos import CentosAnalyzer
from analyzer.system.ubuntu import UbuntuAnalyzer



def test_centos_basic_parse():
    '''
    Test that lines of the form 'curl.x86_64   7.29.0-42.el7' are parsed correctly
    '''
    line = 'curl.x86_64   7.29.0-42.el7'
    pkg_name, pkg_version = CentosAnalyzer.parse_pkg_line(line)
    assert pkg_name == 'curl'
    assert pkg_version == '7.29.0'


def test_centos_epoch_parse():
    '''
    Test that epoch numbers dont mess with parsing 'curl.x86_64   1:7.29.0-42.el7'
    '''
    line = 'curl.x86_64   1:7.29.0-42.el7'
    pkg_name, pkg_version = CentosAnalyzer.parse_pkg_line(line)
    assert pkg_name == 'curl'
    assert pkg_version == '7.29.0'


def test_centos_extra_dash_parse():
    '''
    Test that the edge case with extra dashes we missed the first time around is handled:
    'java-1.8.0-openjdk.x86_64   1:1.8.0.212.b04-0.el7_6'
    '''
    line = 'java-1.8.0-openjdk.x86_64   1:1.8.0.212.b04-0.el7_6'
    pkg_name, pkg_version = CentosAnalyzer.parse_pkg_line(line)
    assert pkg_name == 'java-1.8.0-openjdk'
    assert pkg_version == '1.8.0.212.b04'


def test_ubuntu_parse():
    '''
    Test that lines of the form
    xserver-xorg-video-vesa-hwe-18.04/bionic-updates,now 1:2.4.0-1~18.04.1 amd64 [installed,automatic]
    yelp/bionic,now 3.26.0-1ubuntu2 amd64 [installed,automatic]
    are correctly parsed by the package parser.
    '''
    lines = ['xserver-xorg-video-vesa-hwe-18.04/bionic-updates,now 1:2.4.0-1~18.04.1 amd64 [installed,automatic]',
             'yelp/bionic,now 3.26.0-1ubuntu2 amd64 [installed,automatic]']
    pkg1_name, pkg1_version = UbuntuAnalyzer.parse_pkg_line(lines[0])
    pkg2_name, pkg2_version = UbuntuAnalyzer.parse_pkg_line(lines[1])
    assert pkg1_name == 'xserver-xorg-video-vesa-hwe-18.04'
    assert pkg1_version == '1:2.4.0-1~18.04.1'
    assert pkg2_name == 'yelp'
    assert pkg2_version == '3.26.0-1ubuntu2'
