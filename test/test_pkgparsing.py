from src.prototype import SystemAnalyzer

def test_basic_parse():
    '''
    Test that lines of the form 'curl.x86_64   7.29.0-42.el7' are parsed correctly
    '''
    line = 'curl.x86_64   7.29.0-42.el7'
    pkg_name, pkg_version  = SystemAnalyzer.parse_pkg_line(line)
    assert pkg_name == 'curl'
    assert pkg_version == '7.29.0'

def test_epoch_parse():
    '''
    Test that epoch numbers dont mess with parsing 'curl.x86_64   1:7.29.0-42.el7'
    '''
    line = 'curl.x86_64   1:7.29.0-42.el7'
    pkg_name, pkg_version  = SystemAnalyzer.parse_pkg_line(line)
    assert pkg_name == 'curl'               
    assert pkg_version == '7.29.0'

def test_extra_dash_parse():
    '''
    Test that the edge case with extra dashes we missed the first time around is handled:
    'java-1.8.0-openjdk.x86_64   1:1.8.0.212.b04-0.el7_6'
    '''
    line = 'java-1.8.0-openjdk.x86_64   1:1.8.0.212.b04-0.el7_6'
    pkg_name, pkg_version = SystemAnalyzer.parse_pkg_line(line)
    assert pkg_name == 'java-1.8.0-openjdk'
    assert pkg_version == '1.8.0.212.b04'