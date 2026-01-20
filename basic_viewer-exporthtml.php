<?php
// Database Configuration
define('DB_HOST','localhost');define('DB_USER','root');define('DB_PASS','');define('DB_NAME','voedselbank_almere_avg');define('DB_TABLE','avg_register');
session_start(['cookie_httponly'=>true,'cookie_samesite'=>'Strict']);
if(empty($_SESSION['csrf_token']))$_SESSION['csrf_token']=bin2hex(random_bytes(32));

// Variables
$message='';$records=[];$total=0;$filter_risico=$_GET['risico']??'';$filter_dpia=$_GET['dpia']??'';$search=$_GET['search']??'';
$view_id=intval($_GET['view']??0);$record=null;$export_pdf=isset($_GET['export']);

try {
    $conn=new mysqli(DB_HOST,DB_USER,DB_PASS,DB_NAME);
    if($conn->connect_error)throw new Exception("Database connection failed");
    $conn->set_charset("utf8mb4");

    // Handle PDF Export
    if($export_pdf && isset($_GET['ids'])){
        $ids=array_filter(array_map('intval',explode(',',$_GET['ids'])));
        if(!empty($ids)){
            $placeholders=implode(',',array_fill(0,count($ids),'?'));
            $stmt=$conn->prepare("SELECT * FROM ".DB_TABLE." WHERE id IN($placeholders) ORDER BY id");
            $stmt->bind_param(str_repeat('i',count($ids)),...$ids);
            $stmt->execute();
            $result=$stmt->get_result();
            $export_data=[];
            while($row=$result->fetch_assoc())$export_data[]=$row;
            $stmt->close();
            
            // Generate HTML for PDF
            $html='<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Register Export</title><style>
                body{font-family:DejaVu Sans,Arial,sans-serif;font-size:12px;margin:20px;}
                .header{text-align:center;border-bottom:2px solid #000;padding-bottom:20px;margin-bottom:30px;}
                h1{font-size:22px;margin:0;color:#000;} .subtitle{color:#666;margin-top:5px;}
                .record{page-break-inside:avoid;margin-bottom:25px;border:1px solid #ddd;padding:15px;border-radius:3px;}
                .record-header{background:#000;color:#fff;padding:8px 12px;margin:-15px -15px 15px -15px;border-radius:3px 3px 0 0;}
                .section{margin-bottom:15px;} .section-title{font-weight:bold;border-bottom:1px solid #ddd;padding-bottom:3px;margin-bottom:8px;}
                .field{margin-bottom:6px;} .field-label{font-weight:bold;display:inline-block;width:200px;color:#555;}
                .badge{display:inline-block;padding:2px 6px;border-radius:10px;font-size:10px;font-weight:bold;}
                .badge-hoog{background:#ffeaea;color:#dc3545;} .badge-middel{background:#fff3cd;color:#856404;}
                .badge-laag{background:#e8f5e8;color:#28a745;} .badge-ja{background:#e3f2fd;color:#007bff;}
                .badge-nee{background:#f5f5f5;color:#666;} .footer{text-align:center;margin-top:40px;padding-top:15px;border-top:1px solid #ddd;font-size:10px;color:#666;}
                @media print{.record{page-break-inside:avoid;}}
            </style></head><body>';
            
            $html.='<div class="header"><h1>Register EXPORT</h1><div class="subtitle">Voedselbank Almere - '.date('d-m-Y H:i:s').'</div>
            <div style="margin-top:10px;font-size:11px;">Aantal records: '.count($export_data).'</div></div>';
            
            foreach($export_data as $r){
                $html.='<div class="record"><div class="record-header">RECORD #'.$r['id'].' - '.htmlspecialchars($r['verwerkingsactiviteit']??'').'</div>
                <div class="section"><div class="section-title">Basis Informatie</div>
                <div class="field"><span class="field-label">ID:</span>'.$r['id'].'</div>
                <div class="field"><span class="field-label">Verwerkingsactiviteit:</span>'.nl2br(htmlspecialchars($r['verwerkingsactiviteit']??'')).'</div>
                <div class="field"><span class="field-label">Doel van de verwerking:</span>'.nl2br(htmlspecialchars($r['doel_van_de_verwerking']??'')).'</div>
                <div class="field"><span class="field-label">Wettelijke grondslag:</span>'.nl2br(htmlspecialchars($r['wettelijke_grondslag']??'')).'</div></div>
                <div class="section"><div class="section-title">Gegevens & Betrokkenen</div>
                <div class="field"><span class="field-label">Categorieën persoonsgegevens:</span>'.nl2br(htmlspecialchars($r['categorieen_persoonsgegevens']??'')).'</div>
                <div class="field"><span class="field-label">Categorieën betrokkenen:</span>'.nl2br(htmlspecialchars($r['categorieen_betrokkenen']??'')).'</div>
                <div class="field"><span class="field-label">Categorieën ontvangers:</span>'.nl2br(htmlspecialchars($r['categorieen_ontvangers']??'')).'</div>
                <div class="field"><span class="field-label">Bewaartermijnen:</span>'.nl2br(htmlspecialchars($r['bewaartermijnen']??'')).'</div></div>
                <div class="section"><div class="section-title">Risico & Beveiliging</div>
                <div class="field"><span class="field-label">Risiconiveau:</span><span class="badge badge-'.($r['risiconiveau']??'').'">'.($r['risiconiveau']??'').'</span></div>
                <div class="field"><span class="field-label">DPIA Vereist:</span><span class="badge badge-'.($r['dpia_vereist']??'').'">'.($r['dpia_vereist']??'').'</span></div>
                <div class="field"><span class="field-label">Technische maatregelen:</span>'.nl2br(htmlspecialchars($r['technische_maatregelen']??'')).'</div>
                <div class="field"><span class="field-label">Organisatorische maatregelen:</span>'.nl2br(htmlspecialchars($r['organisatorische_maatregelen']??'')).'</div></div>';
                
                $html.='<div class="section"><div class="section-title">Systeem Informatie</div>
                <div class="field"><span class="field-label">Aangemaakt op:</span>'.($r['created_at']??'').'</div>
                <div class="field"><span class="field-label">Bijgewerkt op:</span>'.($r['updated_at']??'').'</div></div></div>';
            }
            
            $html.='<div class="footer">Export gegenereerd op '.date('d-m-Y H:i:s').' | Pagina 1</div></body></html>';
            
            // Output as downloadable HTML file (users can save as PDF via browser print)
            header('Content-Type: text/html');
            header('Content-Disposition: attachment; filename="AVG_Register_'.date('Y-m-d').'.html"');
            echo $html;
            exit;
        }
    }

    // Handle Delete
    if($_SERVER['REQUEST_METHOD']==='POST'&&($_POST['action']??'')==='delete'){
        if(($_POST['csrf_token']??'')!==$_SESSION['csrf_token'])die('CSRF');
        $ids=array_filter(array_map('intval',$_POST['delete_ids']??[]));
        if($ids){
            $ph=implode(',',array_fill(0,count($ids),'?'));
            $stmt=$conn->prepare("DELETE FROM ".DB_TABLE." WHERE id IN($ph)");
            $stmt->bind_param(str_repeat('i',count($ids)),...$ids);
            if($stmt->execute()){
                $_SESSION['msg']=count($ids)." record(s) verwijderd";
                $_SESSION['type']='success';
            }else{
                $_SESSION['msg']="Verwijderen mislukt";
                $_SESSION['type']='error';
            }
            $stmt->close();
            header("Location: ".$_SERVER['PHP_SELF']);exit;
        }
    }

    // Handle Detailed View
    if($view_id>0){
        $stmt=$conn->prepare("SELECT * FROM ".DB_TABLE." WHERE id = ?");
        $stmt->bind_param('i',$view_id);
        $stmt->execute();
        $result=$stmt->get_result();
        if($result&&$result->num_rows>0)$record=$result->fetch_assoc();
        $stmt->close();
    }

    // Get messages
    if(isset($_SESSION['msg'])&&!$export_pdf){
        $message=$_SESSION['msg'];
        $type=$_SESSION['type']??'';
        unset($_SESSION['msg'],$_SESSION['type']);
    }

    // Fetch records with filters
    if(!$export_pdf){
        $sql="SELECT id,verwerkingsactiviteit,doel_van_de_verwerking,risiconiveau,dpia_vereist,categorieen_persoonsgegevens FROM ".DB_TABLE." WHERE 1=1";
        $params=[];$types='';
        if($search){
            $sql.=" AND (verwerkingsactiviteit LIKE ? OR doel_van_de_verwerking LIKE ? OR categorieen_persoonsgegevens LIKE ?)";
            $params[]="%$search%";$params[]="%$search%";$params[]="%$search%";$types.='sss';
        }
        if(in_array($filter_risico,['laag','middel','hoog'])){
            $sql.=" AND risiconiveau = ?";$params[]=$filter_risico;$types.='s';
        }
        if(in_array($filter_dpia,['ja','nee'])){
            $sql.=" AND dpia_vereist = ?";$params[]=$filter_dpia;$types.='s';
        }
        $sql.=" ORDER BY id DESC";
        
        $stmt=$conn->prepare($sql);
        if($stmt){
            if($params)$stmt->bind_param($types,...$params);
            $stmt->execute();
            $result=$stmt->get_result();
            if($result){
                while($row=$result->fetch_assoc())$records[]=$row;
                $total=$result->num_rows;
            }
            $stmt->close();
        }
        
        // Get statistics
        $stats=['t'=>0,'h'=>0,'m'=>0,'l'=>0,'dj'=>0,'dn'=>0];
        $result=$conn->query("SELECT COUNT(*)t,
            SUM(risiconiveau='hoog')h,SUM(risiconiveau='middel')m,SUM(risiconiveau='laag')l,
            SUM(dpia_vereist='ja')dj,SUM(dpia_vereist='nee')dn FROM ".DB_TABLE);
        if($result&&$row=$result->fetch_assoc())$stats=$row;
    }
    
    $conn->close();
}catch(Exception $e){
    $message="Error: ".$e->getMessage();
    $type='error';
}
?>
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,sans-serif;background:#f8f9fa;color:#222;line-height:1.6;padding:20px;min-height:100vh}
.container{max-width:1400px;margin:0 auto}
.header{background:linear-gradient(135deg,#000 0%,#1a1a1a 100%);color:#fff;padding:28px 32px;margin-bottom:24px;border:1px solid #333;border-radius:4px}
.header h1{font-size:26px;display:flex;align-items:center;gap:14px}
.header h1 i{color:#fff;font-size:24px;background:#333;padding:12px;border-radius:6px}
.header p{color:#ccc;font-size:14px;margin-top:8px}
.stats-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#fff;border:1px solid #ddd;padding:20px;border-radius:4px;display:flex;align-items:center;gap:16px}
.stat-icon{width:48px;height:48px;background:#000;border-radius:6px;display:flex;align-items:center;justify-content:center;color:white;font-size:20px}
.stat-value{font-size:24px;font-weight:600}
.stat-label{font-size:13px;color:#666;text-transform:uppercase}
.stat-card.high-risk .stat-icon{background:#dc3545}
.stat-card.medium-risk .stat-icon{background:#ffc107;color:#000}
.stat-card.low-risk .stat-icon{background:#28a745}
.stat-card.dpia .stat-icon{background:#007bff}
.filters-toolbar{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #ddd;border-radius:4px;display:grid;grid-template-columns:1fr auto auto;gap:16px}
.search-box{position:relative}
.search-box input{width:100%;padding:10px 16px 10px 40px;border:1px solid #ddd;border-radius:4px}
.search-box i{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:#666}
.filter-group{display:flex;gap:12px}
.filter-select{padding:9px 16px;border:1px solid #ddd;border-radius:4px;background:white;min-width:140px}
.risico-badge{padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;display:inline-flex;align-items:center;gap:4px}
.risico-hoog{background:#ffeaea;color:#dc3545}
.risico-middel{background:#fff3cd;color:#856404}
.risico-laag{background:#e8f5e8;color:#28a745}
.dpia-badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600}
.dpia-ja{background:#e3f2fd;color:#007bff}
.dpia-nee{background:#f5f5f5;color:#666}
.toolbar{background:#fff;padding:18px 24px;margin-bottom:20px;border:1px solid #ddd;border-radius:4px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}
.select-all{display:flex;align-items:center;gap:8px}
.selected-count{background:#f0f0f0;padding:5px 12px;border-radius:3px;display:flex;align-items:center;gap:6px;border:1px solid #ddd}
.btn{padding:10px 22px;border:1px solid #000;background:#fff;color:#000;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:8px;text-transform:uppercase;border-radius:4px;text-decoration:none}
.btn:hover{background:#000;color:#fff}
.btn-export{background:#000;color:#fff}
.btn-delete{border-color:#dc3545;color:#dc3545}
.btn-delete:hover{background:#dc3545;color:#fff}
.btn-view{border-color:#007bff;color:#007bff}
.btn-view:hover{background:#007bff;color:#fff}
.btn:disabled{opacity:.5;cursor:not-allowed}
.table-container{background:#fff;border:1px solid #ddd;margin-bottom:24px;border-radius:4px;overflow:hidden}
table{width:100%;border-collapse:collapse}
thead{background:#f5f5f5;border-bottom:2px solid #000}
th{padding:18px 16px;text-align:left;font-weight:600;text-transform:uppercase;border-bottom:1px solid #ddd}
th.checkbox-col{width:50px;text-align:center}
th.id-col{width:70px}
th.risico-col{width:100px}
th.dpia-col{width:80px}
th.actions-col{width:100px}
td{padding:18px 16px;border-bottom:1px solid #eee}
td.checkbox-col{text-align:center}
.text-content{max-height:80px;overflow-y:auto;padding-right:10px}
tbody tr:hover{background:#f9f9f9}
tbody tr.selected{background:#f0f0f0}
input[type="checkbox"]{width:18px;height:18px;cursor:pointer;border:2px solid #000;border-radius:3px;appearance:none}
input[type="checkbox"]:checked{background:#000}
input[type="checkbox"]:checked::after{content:'✓';color:white;font-size:12px;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%)}
.empty-state{text-align:center;padding:60px 20px}
.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:1000;align-items:center;justify-content:center}
.modal{background:#fff;width:450px;max-width:90%;border:1px solid #000;border-radius:4px}
.modal-header{padding:20px;background:#000;color:#fff;display:flex;align-items:center;gap:12px}
.close-modal{background:none;border:none;color:#fff;cursor:pointer}
.modal-body{padding:24px}
.modal-footer{padding:20px;border-top:1px solid #ddd;display:flex;justify-content:flex-end;gap:12px}
.detail-grid{display:grid;gap:20px}
.detail-section{border:1px solid #eee;border-radius:4px;padding:20px}
.detail-section h4{margin-bottom:15px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #eee;padding-bottom:10px}
.detail-field{display:grid;grid-template-columns:200px 1fr;gap:15px;margin-bottom:12px}
.detail-field label{font-weight:600;color:#666}
.footer{text-align:center;padding:24px 20px;color:#666;border-top:1px solid #ddd;background:#fff;margin-top:20px}
.footer-stats{display:flex;justify-content:center;gap:32px;margin-top:16px}
.footer-stat{display:flex;flex-direction:column;align-items:center}
.footer-stat-value{font-size:18px;font-weight:600}
@media(max-width:1100px){.filters-toolbar{grid-template-columns:1fr}.stats-cards{grid-template-columns:repeat(2,1fr)}}
@media(max-width:768px){body{padding:16px}.header{padding:20px}.header h1{font-size:22px;flex-direction:column}
.stats-cards{grid-template-columns:1fr}.toolbar{flex-direction:column}.btn{width:100%;justify-content:center}
.table-container{overflow-x:auto}table{min-width:800px}.footer-stats{flex-direction:column}.detail-field{grid-template-columns:1fr}}
@media(max-width:480px){.filter-group{flex-direction:column}.filter-select{width:100%}.modal{width:95%}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1><i class="fas fa-pills"></i>Register</h1>
<p>Beheer verwerkingsactiviteiten</p>
</div>

<div class="stats-cards">
<div class="stat-card"><div class="stat-icon"><i class="fas fa-database"></i></div><div><div class="stat-value"><?php echo$stats['t']?></div><div class="stat-label">Totaal</div></div></div>
<div class="stat-card high-risk"><div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div><div><div class="stat-value"><?php echo$stats['h']?></div><div class="stat-label">Hoog Risico</div></div></div>
<div class="stat-card medium-risk"><div class="stat-icon"><i class="fas fa-exclamation-circle"></i></div><div><div class="stat-value"><?php echo$stats['m']?></div><div class="stat-label">Middel Risico</div></div></div>
<div class="stat-card low-risk"><div class="stat-icon"><i class="fas fa-check-circle"></i></div><div><div class="stat-value"><?php echo$stats['l']?></div><div class="stat-label">Laag Risico</div></div></div>
<div class="stat-card dpia"><div class="stat-icon"><i class="fas fa-clipboard-check"></i></div><div><div class="stat-value"><?php echo$stats['dj']?></div><div class="stat-label">DPIA Vereist</div></div></div>
</div>

<div class="filters-toolbar">
<div class="search-box">
<i class="fas fa-search"></i>
<form method="GET" style="display:inline">
<input type="text" name="search" placeholder="Zoeken in activiteiten..." value="<?php echo htmlspecialchars($search)?>" onchange="this.form.submit()">
</form>
</div>
<div class="filter-group">
<select class="filter-select" name="risico" onchange="this.form.submit()" form="filterForm">
<option value="">Alle Risico</option>
<option value="hoog"<?php echo$filter_risico=='hoog'?' selected':''?>>Hoog</option>
<option value="middel"<?php echo$filter_risico=='middel'?' selected':''?>>Middel</option>
<option value="laag"<?php echo$filter_risico=='laag'?' selected':''?>>Laag</option>
</select>
<select class="filter-select" name="dpia" onchange="this.form.submit()" form="filterForm">
<option value="">Alle DPIA</option>
<option value="ja"<?php echo$filter_dpia=='ja'?' selected':''?>>DPIA Ja</option>
<option value="nee"<?php echo$filter_dpia=='nee'?' selected':''?>>DPIA Nee</option>
</select>
</div>
<div class="filter-group">
<a href="?" class="btn"><i class="fas fa-times"></i>Reset</a>
<form id="filterForm" method="GET" style="display:none"></form>
</div>
</div>

<?php if($message):?>
<div style="padding:14px 18px;margin-bottom:20px;border-left:3px solid #000;background:#fff;border:1px solid #ddd;display:flex;align-items:center;gap:10px">
<i class="fas fa-<?php echo($type??'')=='success'?'check-circle':'exclamation-circle'?>"></i>
<span><?php echo htmlspecialchars($message)?></span>
</div>
<?php endif?>

<form method="POST" id="mainForm">
<input type="hidden" name="csrf_token" value="<?php echo$_SESSION['csrf_token']?>">
<input type="hidden" name="action" value="delete">

<div class="toolbar">
<div class="selection-info">
<div class="select-all">
<input type="checkbox" id="selectAll">
<label for="selectAll">Selecteer Alles</label>
</div>
<div class="selected-count" id="selectedCount">
<i class="fas fa-check"></i><span>0 geselecteerd</span>
</div>
</div>
<div style="display:flex;gap:12px">
<button type="button" class="btn btn-export" onclick="exportPDF()">
<i class="fas fa-file-pdf"></i>Export HTML
</button>
<button type="button" id="deleteBtn" class="btn btn-delete" disabled>
<i class="fas fa-trash-alt"></i>Verwijder
</button>
</div>
</div>

<div class="table-container">
<?php if($records):?>
<table>
<thead>
<tr>
<th class="checkbox-col"></th>
<th class="id-col">ID</th>
<th>Verwerkingsactiviteit</th>
<th class="risico-col">Risico</th>
<th class="dpia-col">DPIA</th>
<th>Persoonsgegevens</th>
<th class="actions-col">Acties</th>
</tr>
</thead>
<tbody>
<?php foreach($records as $r):?>
<tr>
<td class="checkbox-col"><input type="checkbox" name="delete_ids[]" value="<?php echo$r['id']?>" class="row-checkbox"></td>
<td class="id-col"><?php echo$r['id']?></td>
<td><div class="text-content"><?php echo nl2br(htmlspecialchars($r['verwerkingsactiviteit']??''))?></div></td>
<td>
<?php if($r['risiconiveau']):?>
<span class="risico-badge risico-<?php echo$r['risiconiveau']?>">
<i class="fas fa-<?php echo$r['risiconiveau']=='hoog'?'exclamation-triangle':($r['risiconiveau']=='middel'?'exclamation-circle':'check-circle')?>"></i>
<?php echo ucfirst($r['risiconiveau'])?>
</span>
<?php else:?>-<?php endif?>
</td>
<td>
<?php if($r['dpia_vereist']):?>
<span class="dpia-badge dpia-<?php echo$r['dpia_vereist']?>"><?php echo ucfirst($r['dpia_vereist'])?></span>
<?php else:?>-<?php endif?>
</td>
<td><div class="text-content"><?php echo nl2br(htmlspecialchars($r['categorieen_persoonsgegevens']??''))?></div></td>
<td><button type="button" class="btn btn-view" onclick="viewRecord(<?php echo$r['id']?>)"><i class="fas fa-eye"></i>Bekijk</button></td>
</tr>
<?php endforeach?>
</tbody>
</table>
<?php else:?>
<div class="empty-state">
<i class="fas fa-table"></i>
<h3>Geen Data</h3>
<p>Geen records gevonden<?php if($search||$filter_risico||$filter_dpia):?></p>
<a href="?" class="btn" style="margin-top:16px"><i class="fas fa-times"></i>Reset filters</a>
<?php endif?>
</div>
<?php endif?>
</div>
</form>

<div class="footer">
<p>Register Management Systeem</p>
<div class="footer-stats">
<div class="footer-stat"><div class="footer-stat-value"><?php echo$total?></div><div class="footer-stat-label">Records</div></div>
<div class="footer-stat"><div class="footer-stat-value"><?php echo date('H:i')?></div><div class="footer-stat-label">Tijd</div></div>
<div class="footer-stat"><div class="footer-stat-value"><?php echo date('d-m-Y')?></div><div class="footer-stat-label">Datum</div></div>
</div>
</div>
</div>

<?php if($record):?>
<div class="modal-overlay" id="detailModal">
<div class="modal" style="max-width:800px">
<div class="modal-header">
<i class="fas fa-eye"></i>
<h3>Details - ID: <?php echo$record['id']?></h3>
<button type="button" class="close-modal" onclick="closeDetail()"><i class="fas fa-times"></i></button>
</div>
<div class="modal-body" style="max-height:70vh;overflow-y:auto">
<div class="detail-grid">
<div class="detail-section">
<h4><i class="fas fa-info"></i>Basis Informatie</h4>
<div class="detail-field"><label>Verwerkingsactiviteit:</label><div><?php echo nl2br(htmlspecialchars($record['verwerkingsactiviteit']??''))?></div></div>
<div class="detail-field"><label>Doel van de verwerking:</label><div><?php echo nl2br(htmlspecialchars($record['doel_van_de_verwerking']??''))?></div></div>
<div class="detail-field"><label>Wettelijke grondslag:</label><div><?php echo nl2br(htmlspecialchars($record['wettelijke_grondslag']??''))?></div></div>
</div>
<div class="detail-section">
<h4><i class="fas fa-users"></i>Gegevens & Betrokkenen</h4>
<div class="detail-field"><label>Categorieën persoonsgegevens:</label><div><?php echo nl2br(htmlspecialchars($record['categorieen_persoonsgegevens']??''))?></div></div>
<div class="detail-field"><label>Categorieën betrokkenen:</label><div><?php echo nl2br(htmlspecialchars($record['categorieen_betrokkenen']??''))?></div></div>
<div class="detail-field"><label>Categorieën ontvangers:</label><div><?php echo nl2br(htmlspecialchars($record['categorieen_ontvangers']??''))?></div></div>
<div class="detail-field"><label>Bewaartermijnen:</label><div><?php echo nl2br(htmlspecialchars($record['bewaartermijnen']??''))?></div></div>
</div>
<div class="detail-section">
<h4><i class="fas fa-shield-alt"></i>Risico & Beveiliging</h4>
<div class="detail-field"><label>Risiconiveau:</label><div><span class="risico-badge risico-<?php echo$record['risiconiveau']?>">
<i class="fas fa-<?php echo$record['risiconiveau']=='hoog'?'exclamation-triangle':($record['risiconiveau']=='middel'?'exclamation-circle':'check-circle')?>"></i>
<?php echo ucfirst($record['risiconiveau'])?></span></div></div>
<div class="detail-field"><label>DPIA Vereist:</label><div><span class="dpia-badge dpia-<?php echo$record['dpia_vereist']?>"><?php echo ucfirst($record['dpia_vereist'])?></span></div></div>
<div class="detail-field"><label>Technische maatregelen:</label><div><?php echo nl2br(htmlspecialchars($record['technische_maatregelen']??''))?></div></div>
<div class="detail-field"><label>Organisatorische maatregelen:</label><div><?php echo nl2br(htmlspecialchars($record['organisatorische_maatregelen']??''))?></div></div>
</div>
<div class="detail-section">
<h4><i class="fas fa-history"></i>Systeem Informatie</h4>
<div class="detail-field"><label>Aangemaakt op:</label><div><?php echo$record['created_at']??''?></div></div>
<div class="detail-field"><label>Bijgewerkt op:</label><div><?php echo$record['updated_at']??''?></div></div>
</div>
</div>
</div>
<div class="modal-footer">
<button type="button" class="btn" onclick="closeDetail()"><i class="fas fa-times"></i>Sluiten</button>
<a href="?export=pdf&ids=<?php echo$record['id']?>" class="btn btn-export" target="_blank"><i class="fas fa-file-pdf"></i>Export HTML</a>
</div>
</div>
</div>
<?php endif?>

<div class="modal-overlay" id="deleteModal">
<div class="modal">
<div class="modal-header">
<i class="fas fa-exclamation-triangle"></i>
<h3>Bevestig Verwijderen</h3>
<button type="button" class="close-modal" onclick="closeDelete()"><i class="fas fa-times"></i></button>
</div>
<div class="modal-body">
<p>Verwijder <strong id="deleteCount">0</strong> record(s)? Deze actie kan niet ongedaan gemaakt worden.</p>
</div>
<div class="modal-footer">
<button type="button" class="btn" onclick="closeDelete()">Annuleren</button>
<button type="button" class="btn btn-delete" onclick="confirmDelete()"><i class="fas fa-trash-alt"></i>Verwijder</button>
</div>
</div>
</div>

<script>
let selectAll=document.getElementById('selectAll'),deleteBtn=document.getElementById('deleteBtn'),selectedCount=document.getElementById('selectedCount');
function updateSelection(){let selected=document.querySelectorAll('.row-checkbox:checked'),count=selected.length;
selectedCount.innerHTML=`<i class="fas fa-check"></i><span>${count} geselecteerd</span>`;deleteBtn.disabled=count===0;
document.querySelectorAll('.row-checkbox').forEach(cb=>cb.closest('tr').classList.toggle('selected',cb.checked));
if(count===0){selectAll.checked=false;selectAll.indeterminate=false;}else if(count===document.querySelectorAll('.row-checkbox').length){selectAll.checked=true;selectAll.indeterminate=false;}else{selectAll.checked=false;selectAll.indeterminate=true;}}
selectAll.addEventListener('change',function(){document.querySelectorAll('.row-checkbox').forEach(cb=>cb.checked=this.checked);updateSelection();});
document.querySelectorAll('.row-checkbox').forEach(cb=>cb.addEventListener('change',updateSelection));
deleteBtn.addEventListener('click',function(){let selected=document.querySelectorAll('.row-checkbox:checked').length;
document.getElementById('deleteCount').textContent=selected;document.getElementById('deleteModal').style.display='flex';});
function closeDelete(){document.getElementById('deleteModal').style.display='none';}function confirmDelete(){closeDelete();
deleteBtn.innerHTML='<i class="fas fa-spinner fa-spin"></i>Verwijderen...';deleteBtn.disabled=true;setTimeout(()=>document.getElementById('mainForm').submit(),300);}
function viewRecord(id){window.location.href='?view='+id;}function closeDetail(){window.location.href=window.location.pathname+window.location.search.replace(/[?&]view=\d+/g,'');}
function exportPDF(){let selected=Array.from(document.querySelectorAll('.row-checkbox:checked')).map(cb=>cb.value).join(',');
if(!selected)return alert('Selecteer eerst records');window.open('?export=pdf&ids='+selected,'_blank');}
document.addEventListener('DOMContentLoaded',function(){updateSelection();<?php if($record):?>document.getElementById('detailModal').style.display='flex';<?php endif?>
document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeDelete();closeDetail();}});});
</script>
</body>
</html>
