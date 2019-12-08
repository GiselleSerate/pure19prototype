from src.prototype import SystemAnalyzer

def test_basic_parse():
    '''
    Test that lines of the form 'curl.x86_64   7.29.0-42.el7' are parsed correctly
    '''
    line = 'curl.x86_64   7.29.0-42.el7'
    pkgName, pkgVersion  = SystemAnalyzer.parse_pkg_line(line)
    assert pkgName == 'curl'
    assert pkgVersion == '7.29.0'

def test_epoch_parse():
    '''
    Test that epoch numbers dont mess with parsing 'curl.x86_64   1:7.29.0-42.el7'
    '''
    line = 'curl.x86_64   1:7.29.0-42.el7'
    pkgName, pkgVersion  = SystemAnalyzer.parse_pkg_line(line)
    assert pkgName == 'curl'               
    assert pkgVersion == '7.29.0'
