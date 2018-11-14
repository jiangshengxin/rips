<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			

Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.		

**/

include 'config/general.php';

?><html>
<head>
	<meta charset="UTF-8">
	<link rel="stylesheet" type="text/css" href="css/rips.css" />
	<?php

	foreach($stylesheets as $stylesheet)
	{
		echo "\t<link type=\"text/css\" href=\"css/$stylesheet.css\" rel=\"";
		if($stylesheet != $default_stylesheet) echo "alternate ";
		echo "stylesheet\" title=\"$stylesheet\" />\n";
	}
	?>
	<script src="js/script.js"></script>
	<script src="js/exploit.js"></script>
	<script src="js/hotpatch.js"></script>
	<script src="js/netron.js"></script>
	<title>RIPS - 一个PHP脚本漏洞的静态源代码分析器-</title>
</head>
<body>

<div class="menu">
	<div style="float:left; width:100%;">
	<table width="100%">
	<tr><td width="75%" nowrap>
		<table class="menutable" width="50%" style="float:left;">
		<tr>
			<td nowrap><b>项目/文件路径:</b></td>
			<td colspan="3" nowrap><input type="text" size=80 id="location" value="<?php echo BASEDIR; ?>" title="enter path to PHP file(s)" placeholder="/var/www/">
			</td>
			<td nowrap><input type="checkbox" id="subdirs" value="1" title="check to scan subdirectories" checked/>子目录扫描
			</td>
		</tr>
		<tr>
			<td nowrap>扫描结果等级:</td>
			<td nowrap>
				<select id="verbosity" style="width:100%" title="选择冗长的等级">
					<?php 
					
						$verbosities = array(
							1 => '1. user tainted only',
							2 => '2. file/DB tainted +1',
							3 => '3. show secured +1,2',
							4 => '4. untainted +1,2,3',
							5 => '5. debug mode'
						);
						
						foreach($verbosities as $level=>$description)
						{
							echo "<option value=\"$level\">$description</option>\n";							
						}
					?>
				</select>
			</td>
			<td align="right" nowrap>
			漏洞类型:
			</td>
			<td>
				<select id="vector" style="width:100%" title="select vulnerability type to scan">
					<?php 
					
						$vectors = array(
							'all' 			=> 'All',
							'server' 		=> 'All server-side',							
							'code' 			=> '- Code Execution',
							'exec' 			=> '- Command Execution',
							'file_read' 	=> '- File Disclosure',
							'file_include' 	=> '- File Inclusion',							
							'file_affect' 	=> '- File Manipulation',
							'ldap' 			=> '- LDAP Injection',
							'unserialize' 	=> '- PHP Object Injection',
							'connect'		=> '- Protocol Injection',							
							'ri'		 	=> '- Reflection Injection',
							'database' 		=> '- SQL Injection',
							'xpath' 		=> '- XPath Injection',
							'other' 		=> '- other',
							'client' 		=> 'All client-side',
							'xss' 			=> '- Cross-Site Scripting',
							'httpheader'	=> '- HTTP Response Splitting',
							'fixation'		=> '- Session Fixation',
							//'crypto'		=> 'Crypto hints'
						);
						
						foreach($vectors as $vector=>$description)
						{
							echo "<option value=\"$vector\" ";
							if($vector == $default_vector) echo 'selected';
							echo ">$description</option>\n";
						}
					?>
				</select>
			</td>
			<td><input type="button" value="开始扫描" style="width:100%" class="Button" onClick="scan(false);" title="start scan" /></td>
		</tr>
		<tr>
			<td nowrap>扫描结果展示风格:</td>
			<td nowrap>
				<select name="stylesheet" id="css" onChange="setActiveStyleSheet(this.value);" style="width:49%" title="select color schema for scan result">
					<?php 
						foreach($stylesheets as $stylesheet)
						{
							echo "<option value=\"$stylesheet\" ";
							if($stylesheet == $default_stylesheet) echo 'selected';
							echo ">$stylesheet</option>\n";
						}
					?>	
				</select>
				<select id="treestyle" style="width:49%" title="select direction of code flow in scan result">
					<option value="1">bottom-up</option>
					<option value="2">top-down</option>
				</select>	
			</td>	
			<td align="right">
				/正则过滤结果/:
			</td>
			<td>
				<input type="text" id="search" style="width:100%" />
			</td>
			<td>
				<input type="button" class="Button" style="width:100%" value="查询" onClick="search()" title="search code by regular expression" />
			</td>
		</tr>
		</table>
		<div id="options" style="margin-top:-10px; display:none; text-align:center;" >
			<p class="textcolor">windows</p>
			<input type="button" class="Button" style="width:50px" value="files" onClick="openWindow(5);eval(document.getElementById('filegraph_code').innerHTML);" title="show list of scanned files" />
			<input type="button" class="Button" style="width:80px" value="user input" onClick="openWindow(4)" title="show list of user input" /><br />
			<input type="button" class="Button" style="width:50px" value="stats" onClick="document.getElementById('stats').style.display='block';" title="show scan statistics" />
			<input type="button" class="Button" style="width:80px" value="functions" onClick="openWindow(3);eval(document.getElementById('functiongraph_code').innerHTML);" title="show list of user-defined functions" />
		</div>
	</td>
	<td width="25%" align="center" valign="center" nowrap>
		<!-- Logo by Gareth Heyes -->
		<div class="logo"><a id="logo" href="http://sourceforge.net/projects/rips-scanner/files/" target="_blank" title="get latest version"><?php echo VERSION ?></a></div>
	</td></tr>
	</table>
	</div>
	
	<div style="clear:left;"></div>
</div>
<div class="menushade"></div>

<div class="scanning" id="scanning">scanning ...
<div class="scanned" id="scanned"></div>
</div>

<div id="result">

    <div style="margin-left:30px;color:#000000;font-size:14px">
        <h3><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">快速开始：</font></font></h3>
        <p><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">找到您当地的PHP源代码</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">路径/文件</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">（例如</font></font><em><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">/ var / www / project1 /</font></font></em><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">或</font></font><em><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">/var/www/index.php</font></font></em><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">），选择</font><font style="vertical-align: inherit;">您要查找</font><font style="vertical-align: inherit;">的</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">漏洞类型</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">，然后单击</font></font><u><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">扫描</font></font></u><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">！</font></font><br><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">
                    检查</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">子目录</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">以包括扫描中的所有子目录。</font><font style="vertical-align: inherit;">建议仅扫描项目的根目录。</font><font style="vertical-align: inherit;">当PHP代码包含时，子目录中的文件将由RIPS自动扫描。</font><font style="vertical-align: inherit;">但是，启用</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">子目录</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">可以改善扫描结果和包含成功率（显示在结果中）。</font></font></p>
        <h3><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">高级：</font></font></h3>
        <p><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">通过选择不同的</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">详细级别来</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">调试错误或改善扫描结果</font><font style="vertical-align: inherit;">（建议使用默认级别1）。</font></font><br><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">
                    扫描完成后，右上角会出现4个新按钮。</font><font style="vertical-align: inherit;">您可以通过在</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">统计信息</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">窗口中</font><font style="vertical-align: inherit;">单击其名称来选择已找到的不同类型的漏洞</font><font style="vertical-align: inherit;">。</font><font style="vertical-align: inherit;">您可以点击</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">用户输入</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">右上角拿到的入口点的列表，</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">功能</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">为所有用户定义的函数或列表和图形</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">文件</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">的所有扫描的文件列表和图表及其包含。</font><font style="vertical-align: inherit;">所有列表都引用到代码查看器。</font></font></p>
        <h3><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">样式：</font></font></h3>
        <p><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">通过选择不同的</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">代码样式，</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">即时更改语法高亮模式</font><font style="vertical-align: inherit;">。</font></font><br><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">
                    在扫描之前，您可以选择应显示代码流的方式：</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">自下而上</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">或</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">自上而下</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">。</font></font></p>
        <h3><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">图标：</font></font></h3>
        <ul>
            <li class="userinput"><font color="black"><b><font style="vertical-align: inherit;"></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">在此行中找到了</font><b><font style="vertical-align: inherit;">用户输入</font></b><font style="vertical-align: inherit;">。</font><font style="vertical-align: inherit;">漏洞利用的潜在切入点。</font></font></font></li>
            <li class="functioninput"><font color="black"><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">漏洞利用取决于</font><font style="vertical-align: inherit;">传递给此行中声明的函数</font><font style="vertical-align: inherit;">的</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">参数</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">。</font><font style="vertical-align: inherit;">看看扫描结果中的调用。</font></font><br><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">单击</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">⇑</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">或</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">⇓</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">跳转到下一个声明或调用此函数。</font></font></font></li>
            <li class="validated"><font color="black"><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">已在此行中检测到</font><font style="vertical-align: inherit;">用户实施的</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">安全措施</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">。</font><font style="vertical-align: inherit;">这可能会阻止剥削。</font></font></font></li>
        </ul>
        <h3><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">选项：</font></font></h3>
        <ul>
            <li><div class="fileico"></div><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">&nbsp;单击文件图标以打开</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">代码查看器</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">以查看原始代码。</font><font style="vertical-align: inherit;">将打开一个新窗口，其中突出显示所有相关行。</font></font><br><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">
                        通过鼠标悬停或持续点击变量暂时突出显示变量。</font><font style="vertical-align: inherit;">单击该调用，跳转到用户定义函数的代码。</font><font style="vertical-align: inherit;">单击</font><font style="vertical-align: inherit;">代码查看器底部的</font></font><u><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">return</font></font></u><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">以跳回。</font><font style="vertical-align: inherit;">这也适用于嵌套函数调用。</font></font></li>
            <li><div class="minusico"></div><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">&nbsp;单击最小化图标以</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">隐藏</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">特定代码跟踪。</font><font style="vertical-align: inherit;">您可以稍后再次单击该图标来显示它。</font></font></li>
            <li><div class="exploit"></div><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">&nbsp;单击目标图标以打开</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">Exploit Creator</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">。</font><font style="vertical-align: inherit;">将打开一个新窗口，您可以在其中输入漏洞利用详细信息并创建PHP Curl漏洞利用代码。</font></font></li>
            <li><div class="help"></div><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">&nbsp;单击帮助图标以获取</font><font style="vertical-align: inherit;">此漏洞类型</font><font style="vertical-align: inherit;">的</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">描述</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">，示例代码，示例利用，修补程序和相关的安全功能。</font></font></li>
            <li><div class="dataleak"></div><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">&nbsp;单击数据泄漏图标以检查受污染的接收器的输出是否在</font><font style="vertical-align: inherit;">某处</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">泄漏</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">（通过echo / print嵌入到HTTP响应中）。</font></font></li>
        </ul>
        <h3><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">提示：</font></font></h3>
        <ul>
            <li><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">RIPS实现</font></font><i><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">静态</font></font></i><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">源代码分析。</font><font style="vertical-align: inherit;">它只扫描源代码文件，不会执行代码。</font></font></li>
            <li><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">此版本不支持面向对象的代码（类）。</font></font></li>
            <li><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">确保RIPS对要扫描的文件具有文件权限。</font></font></li>
            <li><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">不要将RIPS的Web界面打开到公共互联网。</font><font style="vertical-align: inherit;">仅</font><font style="vertical-align: inherit;">在</font></font><b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">本地</font></font></b><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">网络服务器</font><font style="vertical-align: inherit;">上使用它</font><font style="vertical-align: inherit;">。</font></font></li>
            <li><font style="vertical-align: inherit;"><font style="vertical-align: inherit;">仅用Firefox测试过。</font></font></li>
        </ul>
    </div>
	
</div>

</body>
</html>