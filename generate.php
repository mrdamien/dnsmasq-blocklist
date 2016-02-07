<?php
class FileScanner
{
    private $rs;
    
    public function FileScanner ($rs)
    {
        $this->rs = $rs;
    }
    
    public function next ()
    {
        do {
            $line = fgets($this->rs);
            if ($line == false)
                return false;
            
            $line = trim($line);
            if (strlen($line) === 0 || $line[0] === '#')
                continue;
            
            $space1 = strpos($line, ' ')+1;
            $space2 = strpos($line, ' ', $space1+1);
            return trim($space2 !== false 
                ? substr($line, $space1, $space2 - $space1)
                : substr($line, $space1));
            
        } while (true);
    }
    
    public function __destruct() 
    {
        fclose($this->rs);
    }
}

class Writer
{
    public function __construct ($rs)
    {
        $this->fp = fopen($rs, 'w');
    }
    
    public function write ($d)
    {
        fwrite($this->fp, sprintf('address="/%s/0.0.0.0"%s', $d, "\n"));
    }
    
    public function __destruct() 
    {
        fclose($this->fp);
    }
}

class Domain
{
    private $domain;
    private $children;
    private $parent = null;
    private $whitelist = false;
    private $whitelistcount = 0;
    
    public function Domain($d) 
    {
        $this->domain = trim($d);
        $this->children = [];
    }
    
    public function setWhitelist ()
    {
        $this->whitelist = true;
        for($i = $this; $i->getParent() !== null; $i = $i->getParent()) {
            $i->addWhitelist();
        }
    }
    
    public function addWhitelist ()
    {
        $this->whitelistcount++;
    }
    
    public function hasWhitelist ()
    {
        return $this->whitelistcount;
    }
    
    public function isWhitelist ()
    {
        return $this->whitelist;
    }
    
    public function getDomain ()
    {
        return $this->domain;
    }
    
    public function setParent (Domain $p)
    {
        $this->parent = $p;
    }
    
    public function getParent ()
    {
        return $this->parent;
    }
    
    public function addSub (Domain $domain)
    {
        $domain->setParent($this);
        $this->children[$domain->getDomain()] = $domain;
    }
    
    public function get ($d)
    {
        if (isset($this->children[$d]))
            return $this->children[$d];
        
        return null;
    }
    
    public function count()
    {
        return count($this->children);
    }
    
    public function addDomain ($domain)
    {
        $parts = explode('.', $domain);
        $last = array_pop($parts);
        
        if (!$this->get($last)) {
            $sub = new Domain($last);
            $this->addSub($sub);
        }
        $domain = implode('.', $parts);
        if ($domain) {
            return $this->get($last)->addDomain($domain);
        }
        
        return $this->get($last);
    }
    
    public function toString ()
    {
        $parts = [];
        for($i = $this; $i->getParent() !== null; $i = $i->getParent()) {
            $parts[] = $i->getDomain();
        }
        return implode('.', $parts);
    }
    
    public function getChildren ()
    {
        reset($this->children);
        return $this->children;
    }
    
    public function shouldBlock ()
    {
        if ($this->isWhitelist())
            return false;
        
        return $this->count() == 0;
    }
    
    public function shouldBlockAll ()
    {
        if ($this->isWhitelist() || $this->hasWhitelist())
            return false;
        
        if ($this->blockAll) // blacklist priority
            return true;
        
        if ($this->count() == 0)
            return true;
        
        return $this->count() >= 3;
    }
    
    private $blockAll = false;
    
    public function blockAll()
    {
        $this->blockAll = true;
    }
    
    public static function find (Domain $root, $find) {
        if ($find === "")
            return $root;
        $parts = explode('.', $find);
        $last = array_pop($parts);
        $find = implode('.', $parts);
        return Domain::find($root->get($last), $find);
    }
}

$root = new Domain('');

function domainIterate($domain, $writer, $depth = 0)
{
    foreach ($domain->getChildren() as $sub)
    {
        if ($sub->shouldBlockAll()) {
            $writer->write('.'.$sub->toString());
        } else {
            domainIterate($sub, $writer, $depth + 1);
            if ($sub->shouldBlock()) {
                $writer->write(($depth==0 ? '.' : '') . $sub->toString());
            }
        }
    }
}


echo "Downloading hosts.zip\n";
$url = 'http://winhelp2002.mvps.org/hosts.zip';
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$output = curl_exec($ch);
file_put_contents('temp.zip', $output);

echo "Unziping file\n";
$zip = new ZipArchive;
$res = $zip->open('temp.zip');
$zip->extractTo('./', 'HOSTS');
$zip->close();


$rs = fopen('HOSTS', 'r');
$in = new FileScanner($rs);
while (($domain = $in->next()) !== false) {
    $root->addDomain($domain);
}



$blacklist = file('blacklist.txt');
foreach ($blacklist as $block) {
    $domain = $root->addDomain(trim(trim($block), '.'));
    if ($block[0] === ".")
        $domain->blockAll();
}

$whitelist = file('whitelist.txt');
foreach ($whitelist as $allow) {
    $domain = $root->addDomain(trim($allow));
    $domain->setWhitelist();
}

$writer = new Writer('hosts.txt');
foreach ($root->getChildren() as $tld)
    domainIterate($tld, $writer);


echo "Done\n";