<?php
session_start();
date_default_timezone_set('Europe/Amsterdam');

$db_config = [
    'host' => 'localhost',
    'username' => 'root',
    'password' => '',
    'database' => 'database_name',
    'table' => 'avg_register',
    'users_table' => 'system_users',
    'changes_table' => 'system_changes',
    'dpia_table' => 'dpia_registrations',
    'mfa_table' => 'user_mfa'
];

$user_roles = [
    'admin' => ['view', 'add', 'edit', 'delete', 'manage_users', 'view_changes', 'manage_dpia', 'export', 'print', 'manage_mfa'],
    'editor' => ['view', 'add', 'edit', 'view_own_changes', 'manage_dpia', 'print'],
    'viewer' => ['view', 'print']
];

$rot47_columns = [
    'naam_verwerkingsverantwoordelijke',
    'contact_verwerkingsverantwoordelijke',
    'naam_gezamenlijke_verwerkingsverantwoordelijke',
    'contact_gezamenlijke_verwerkingsverantwoordelijke',
    'naam_vertegenwoordiger',
    'contact_vertegenwoordiger',
    'naam_fg',
    'contact_fg'
];

$recent_update_threshold = 180;

function t($key, $params = []) {
    $translations = [
        'site_name' => 'AVG REGISTER', 'welcome' => 'GDPR Compliance Database', 'login' => 'Login',
        'logout' => 'Logout', 'save' => 'Save', 'edit' => 'Edit', 'delete' => 'Delete', 'view' => 'View',
        'add' => 'Add', 'create' => 'Create', 'update' => 'Update', 'search' => 'Search', 'clear' => 'Clear',
        'export' => 'Export', 'back' => 'Back', 'cancel' => 'Cancel', 'actions' => 'Actions', 'status' => 'Status',
        'dashboard' => 'Dashboard', 'processing_activities' => 'Processing Activities', 'data_breaches' => 'Data Breaches',
        'audit_trail' => 'Audit Trail', 'reports' => 'Reports', 'settings' => 'Settings', 'language' => 'Language',
        'total_activities' => 'Total Records', 'active_activities' => 'Active Records', 'high_risk' => 'High Risk',
        'international_transfers' => 'International', 'open_breaches' => 'Open Issues', 'pending_dpias' => 'Pending Reviews',
        'view_all' => 'View All', 'recent_activities' => 'Recent Activities', 'add_activity' => 'Add New Record',
        'activity_name' => 'Record Name', 'legal_basis' => 'Legal Basis', 'purpose' => 'Purpose', 'data_categories' => 'Data Categories',
        'data_subjects' => 'Data Subjects', 'recipients' => 'Recipients', 'retention_period' => 'Retention Period',
        'security_measures' => 'Security Measures', 'risk_level' => 'Risk Level', 'third_country_transfers' => 'Intl. Transfers',
        'dpi_required' => 'DPIA Required', 'safeguards' => 'Safeguards', 'low' => 'Low', 'medium' => 'Medium', 'high' => 'High',
        'under_review' => 'Under Review', 'active' => 'Active', 'inactive' => 'Inactive', 'all' => 'All', 'yes' => 'Yes', 'no' => 'No',
        'success' => 'Success', 'error' => 'Error', 'warning' => 'Warning', 'info' => 'Info', 'confirm_delete' => 'Are you sure you want to delete this item?',
        'confirm_document_delete' => 'Are you sure you want to delete this document?', 'enter_password' => 'Enter access password',
        'invalid_password' => 'Invalid password', 'operation_completed' => 'Operation completed successfully', 'item_deleted' => 'Item deleted successfully',
        'new' => 'New', 'system' => 'System', 'created' => 'Created', 'updated' => 'Updated', 'last_updated' => 'Last Updated',
        'select_legal_basis' => 'Select Legal Basis', 'all_activities' => 'All activities', 'recent_user_activity' => 'Recent User Activity',
        'system_audit_trail' => 'System Audit Trail', 'view_full_log' => 'View Full Log', 'timestamp' => 'Timestamp', 'action' => 'Action',
        'entity_type' => 'Entity Type', 'entity_id' => 'Entity ID', 'details' => 'Details', 'user_ip' => 'IP Address', 'user_agent' => 'User Agent',
        'total_log_entries' => 'Total Log Entries', 'unique_ip_addresses' => 'Unique IP Addresses', 'unique_actions' => 'Unique Actions',
        'oldest_log' => 'Oldest Log', 'filter_logs' => 'Filter Logs', 'action_type' => 'Action Type', 'date_from' => 'Date From', 'date_to' => 'Date To',
        'filter' => 'Filter', 'login_successful' => 'Login successful', 'login_failed' => 'Failed login attempt', 'database_error' => 'Database error',
        'no_audit_entries' => 'No audit log entries found', 'changes' => 'Changes', 'added_activity' => 'Added processing activity',
        'updated_activity' => 'Updated processing activity', 'deleted_activity' => 'Deleted processing activity', 'viewed_activity' => 'Viewed activity',
        'listed_processing_activities' => 'Listed processing activities', 'searched_for' => 'Searched for', 'found_results' => 'found',
        'exported_to' => 'Exported to', 'with_filters' => 'with filters', 'audit_logs_cleaned' => 'Audit logs cleaned up successfully.',
        'records_removed' => 'records removed', 'error_cleaning_logs' => 'Error cleaning up audit logs.', 'confirm_cleanup_logs' => 'Are you sure you want to cleanup audit logs older than {days} days?',
        'cleanup_old_logs' => 'Cleanup Old Logs', 'list_view' => 'List View', 'manage_users' => 'Manage Users', 'user_management' => 'User Management',
        'add_new_user' => 'Add New User', 'username' => 'Username', 'password' => 'Password', 'email' => 'Email', 'full_name' => 'Full Name',
        'role' => 'Role', 'is_active' => 'Active', 'last_login' => 'Last Login', 'user_actions' => 'User Actions', 'edit_user' => 'Edit User',
        'delete_user' => 'Delete User', 'confirm_user_delete' => 'Are you sure you want to delete this user?', 'cannot_delete_self' => 'You cannot delete your own account!',
        'encrypted_indicator' => '[ENCRYPTED]', 'home' => 'Home', 'refresh' => 'Refresh', 'review_mode' => 'Review Mode', 'toggle_compact_view' => 'Toggle Compact View',
        'row_counter' => 'Showing {current} of {total} rows', 'encrypted_columns' => 'Encrypted columns', 'user' => 'User', 'add_record_form' => 'Add New Record',
        'edit_record_form' => 'Edit Record', 'record_id' => 'Record ID', 'created_at' => 'Created At', 'updated_at' => 'Updated At', 'timestamps' => 'Timestamps',
        'automatically_set' => 'Automatically set', 'automatically_updated' => 'Automatically updated', 'original_date_kept' => 'Original date kept',
        'view_changes' => 'View Changes', 'recent_changes' => 'Recent Changes', 'action_type' => 'Action Type', 'table' => 'Table', 'changed_fields' => 'Changed Fields',
        'old_data' => 'Old Data', 'new_data' => 'New Data', 'close' => 'Close', 'admin' => 'Admin', 'editor' => 'Editor', 'viewer' => 'Viewer',
        'role_admin' => 'Administrator', 'role_editor' => 'Editor', 'role_viewer' => 'Viewer', 'no_permission_view' => 'You don\'t have permission to view data.',
        'no_activities_found' => 'No processing activities found', 'change_details' => 'Change Details', 'of' => 'of', 'existing_users' => 'Existing Users',
        'vertical_view' => 'Vertical View', 'table_view' => 'Table View', 'view_record' => 'View Record', 'edit_record' => 'Edit Record',
        'previous_record' => 'Previous', 'next_record' => 'Next', 'record_navigation' => 'Record Navigation', 'vertical_display' => 'Vertical Display',
        'record_details' => 'Record Details', 'back_to_table' => 'Back to Table', 'jump_to_record' => 'Jump to record', 'record' => 'Record',
        'first_four_columns' => 'First 4 columns', 'full_details' => 'Full Details', 'showing_columns' => 'Showing columns', 'only_in' => 'only in',
        'view_only_in' => 'View only in', 'dpia_management' => 'DPIA Management', 'dpia_registrations' => 'DPIA Registrations', 'view_dpias' => 'View DPIAs',
        'register_dpia' => 'Register DPIA', 'dpia_status' => 'DPIA Status', 'has_dpia' => 'Has DPIA', 'no_dpia' => 'No DPIA', 'dpia_registered' => 'DPIA Registered',
        'dpia_registered_on' => 'DPIA Registered on', 'dpia_registered_by' => 'DPIA Registered by', 'register_record_dpia' => 'Register Record for DPIA',
        'dpia_already_registered' => 'DPIA already registered for this record', 'dpia_registration_success' => 'DPIA registration successful',
        'remove_dpia' => 'Remove DPIA', 'confirm_remove_dpia' => 'Are you sure you want to remove DPIA registration for this record?',
        'dpia_removed' => 'DPIA registration removed', 'dpia_description' => 'Description', 'necessity_proportionality' => 'Necessity and Proportionality',
        'mitigation_measures' => 'Mitigation Measures', 'residual_risk' => 'Residual Risk After Mitigation', 'overall_risk_level' => 'Overall Risk Level',
        'dpia_status_field' => 'Status', 'dpia_open' => 'Open', 'dpia_closed' => 'Closed', 'dpia_pending' => 'Pending', 'add_dpia' => 'Add DPIA',
        'edit_dpia' => 'Edit DPIA', 'delete_dpia' => 'Delete DPIA', 'view_dpia' => 'View DPIA', 'dpia_details' => 'DPIA Details',
        'dpia_for_record' => 'DPIA for Record', 'registered_date' => 'Registered Date', 'last_updated' => 'Last Updated', 'notes' => 'Notes',
        'no_dpias_found' => 'No DPIA registrations found', 'all_dpias' => 'All DPIAs', 'open_dpias' => 'Open DPIAs', 'closed_dpias' => 'Closed DPIAs',
        'pending_dpias' => 'Pending DPIAs', 'filter_by_status' => 'Filter by Status', 'dpia_id' => 'DPIA ID', 'back_to_dpias' => 'Back to DPIAs',
        'processing_activity_name' => 'Processing Activity', 'organizational_measures' => 'Organizational Measures', 'technical_measures' => 'Technical Measures',
        'records_to_update' => 'Records to Update', 'update_recommendations' => 'Update Recommendations', 'not_updated_recently' => 'Not recently updated',
        'days_ago' => 'days ago', 'recommendation_threshold' => 'Recommendation Threshold', 'update_required' => 'Update Required', 'add_new' => 'Add New',
        'edit_existing' => 'Edit Existing', 'recommend_to_edit' => 'Recommend to Edit', 'recommendation_info' => 'Records not updated in the last {days} days',
        'add_button_menu' => 'Add/Edit Menu', 'last_update' => 'Last Update', 'never_updated' => 'Never updated', 'recently_updated' => 'Recently updated',
        'update_status' => 'Update Status', 'needs_update' => 'Needs Update', 'up_to_date' => 'Up to Date', 'updated_long_ago' => 'Updated long ago',
        'update_frequency' => 'Update Frequency', 'update_statistics' => 'Update Statistics', 'records_need_update' => 'records need update',
        'records_up_to_date' => 'records up to date', 'average_update_age' => 'Average update age', 'oldest_update' => 'Oldest update',
        'newest_update' => 'Newest update', 'update_history' => 'Update History', 'days_since_update' => 'Days since update', 'update_priority' => 'Update Priority',
        'high_priority' => 'High Priority', 'medium_priority' => 'Medium Priority', 'low_priority' => 'Low Priority', 'no_update_data' => 'No update data available',
        'update_reminder' => 'Update Reminder', 'update_due' => 'Update due', 'overdue_by' => 'Overdue by', 'update_schedule' => 'Update Schedule',
        'update_monitoring' => 'Update Monitoring', 'update_analytics' => 'Update Analytics', 'update_tracking' => 'Update Tracking',
        'update_management' => 'Update Management', 'update_notifications' => 'Update Notifications', 'update_alerts' => 'Update Alerts',
        'update_warnings' => 'Update Warnings', 'this_record_not_updated' => 'This record has not been updated for {days} days (threshold: {threshold} days)',
        'update_now' => 'Update Now', 'auto_populated' => 'Auto-populated', 'mitigation_measures_from_record' => 'Mitigation measures from record',
        'refresh_measures' => 'Refresh measures', 'print' => 'Print', 'print_record' => 'Print Record', 'print_full_details' => 'Full Details Print',
        'print_compact' => 'Compact Print', 'compact_view' => 'Compact View', 'compact_print_description' => 'Table-based compact view for printing',
        'full_print_description' => 'Full details with all columns', 'confidential' => 'CONFIDENTIAL - CONFIDENTIAL - CONFIDENTIAL',
        'generated_on' => 'Generated on', 'generated_by' => 'Generated by', 'page' => 'Page', 'print_summary' => 'Print Summary',
        'show_all_columns' => 'Show All Columns', 'show_compact' => 'Show Compact', 'print_compact_table' => 'Print Compact Table',
        'print_individual' => 'Print Individual Record', 'print_all' => 'Print All Records', 'print_options' => 'Print Options',
        'print_full' => 'Print Full Details', 'dpia_focused_print' => 'DPIA Focused Print', 'print_dpia_details' => 'Print DPIA Details',
        'dpia_print_description' => 'Includes DPIA risk assessment and mitigation details', 'print_with_dpia_details' => 'Print with DPIA risk assessment details',
        'residual_risk_summary' => 'Residual Risk Summary', 'risk_assessment' => 'Risk Assessment',
        'avg_registersovereenkomstmetderdepartij' => 'Agreement with Third Party', 'wijzijnverwerker' => 'We are Processor',
        'update_needed_column' => 'Update Needed', 'columns_shown' => 'Columns shown', 'field' => 'Field', 'value' => 'Value',
        'click_record_print' => 'Click on a record\'s print button below', 'printing_options' => 'Printing Options',
        'print_individual_record' => 'Print Individual Record', 'sensitive_data_removed' => 'Sensitive data removed for printing',
        'sensitive_columns_excluded' => 'Sensitive columns excluded', 'print_safe_version' => 'Print Safe Version',
        'excluded_columns' => 'Excluded Columns', 'safe_for_printing' => 'Safe for printing', 'showing_safe_data' => 'Showing safe data only',
        'sensitive_information' => 'Sensitive Information', 'protected_for_privacy' => 'Protected for privacy',
        'add_new' => 'Add New', 'records' => 'Records', 'page' => 'Page', 'print_all_records' => 'Print All Records',
        'secure_print' => 'Secure Print', 'print_all_with_dpia' => 'Print All Records with DPIA Details',
        'print_all_with_dpia_description' => 'Secure print of all records including DPIA risk assessments',
        'generating_print' => 'Generating print documents...', 'print_batch' => 'Print Batch', 'include_all_records' => 'Include All Records',
        'include_only_with_dpia' => 'Include Only Records with DPIA', 'print_selection' => 'Print Selection',
        'print_all_secure' => 'Print All Records Securely', 'generating_multiple_records' => 'Generating {count} records for printing',
        'batch_print_progress' => 'Processing record {current} of {total}', 'print_complete' => 'Print generation complete',
        'download_print_package' => 'Download Print Package', 'view_print_preview' => 'View Print Preview', 'start_print_job' => 'Start Print Job',
        'cancel_print_job' => 'Cancel Print Job', 'print_job_status' => 'Print Job Status', 'records_in_batch' => 'Records in batch',
        'estimated_pages' => 'Estimated pages', 'print_quality' => 'Print Quality', 'print_speed' => 'Print Speed', 'duplex_printing' => 'Duplex Printing',
        'collate_documents' => 'Collate Documents', 'print_range' => 'Print Range', 'all_pages' => 'All Pages', 'current_page' => 'Current Page',
        'custom_range' => 'Custom Range', 'from_page' => 'From page', 'to_page' => 'To page', 'print_settings' => 'Print Settings',
        'margins' => 'Margins', 'orientation' => 'Orientation', 'portrait' => 'Portrait', 'landscape' => 'Landscape', 'paper_size' => 'Paper Size',
        'a4' => 'A4', 'letter' => 'Letter', 'legal' => 'Legal', 'scale_to_fit' => 'Scale to fit', 'headers_footers' => 'Headers & Footers',
        'print_header' => 'Print Header', 'print_footer' => 'Print Footer', 'page_numbers' => 'Page Numbers', 'watermark' => 'Watermark',
        'draft' => 'Draft', 'normal' => 'Normal', 'high_quality' => 'High Quality', 'print_preview' => 'Print Preview', 'print_now' => 'Print Now',
        'save_as_pdf' => 'Save as PDF', 'send_to_printer' => 'Send to Printer', 'print_dialog' => 'Print Dialog', 'print_queued' => 'Print Queued',
        'print_in_progress' => 'Print in Progress', 'print_completed' => 'Print Completed', 'print_failed' => 'Print Failed',
        'retry_print' => 'Retry Print', 'cancel_printing' => 'Cancel Printing', 'print_log' => 'Print Log', 'last_printed' => 'Last Printed',
        'printed_by' => 'Printed By', 'print_count' => 'Print Count', 'paper_used' => 'Paper Used', 'ink_level' => 'Ink Level',
        'printer_status' => 'Printer Status', 'ready' => 'Ready', 'busy' => 'Busy', 'offline' => 'Offline', 'error' => 'Error',
        'out_of_paper' => 'Out of Paper', 'low_ink' => 'Low Ink', 'jam' => 'Jam', 'maintenance_required' => 'Maintenance Required',
        'batch_print_summary' => 'Batch Print Summary', 'records_with_dpia' => 'Records with DPIA', 'batch_report' => 'Batch Report',
        'dpia_vereist' => 'DPIA Vereist', 'back_to_home' => 'Back to Home',
        // MFA Translations
        'mfa_management' => 'MFA Management',
        'mfa_enabled' => 'MFA Enabled',
        'mfa_disabled' => 'MFA Disabled',
        'enable_mfa' => 'Enable MFA',
        'disable_mfa' => 'Disable MFA',
        'regenerate_backup_codes' => 'Regenerate Backup Codes',
        'enter_mfa_code' => 'Enter MFA Code',
        'mfa_code' => 'MFA Code',
        'mfa_required' => 'MFA Required',
        'mfa_setup' => 'MFA Setup',
        'mfa_secret_key' => 'Secret Key',
        'copy_secret_key' => 'Copy Secret Key',
        'backup_codes' => 'Backup Codes',
        'save_backup_codes' => 'Save these backup codes securely',
        'mfa_invalid_code' => 'Invalid MFA code',
        'mfa_enabled_success' => 'MFA enabled successfully',
        'mfa_disabled_success' => 'MFA disabled successfully',
        'backup_codes_regenerated' => 'Backup codes regenerated',
        'use_backup_code' => 'Use Backup Code',
        'mfa_backup_code' => 'Backup Code',
        'invalid_backup_code' => 'Invalid backup code',
        'mfa_status' => 'MFA Status',
        'mfa_admin_management' => 'MFA Admin Management',
        'user_mfa_status' => 'User MFA Status',
        'force_mfa_enable' => 'Force Enable MFA',
        'force_mfa_disable' => 'Force Disable MFA',
        'mfa_forced_enabled' => 'MFA force-enabled by admin',
        'mfa_forced_disabled' => 'MFA force-disabled by admin',
        'require_mfa_setup' => 'Require MFA Setup',
        'mfa_setup_required' => 'MFA setup required before login',
        'mfa_not_setup' => 'MFA not configured',
        'setup_mfa_now' => 'Setup MFA Now',
        'verify' => 'Verify',
        'mfa_verify' => 'Verify MFA'
    ];
    
    $translation = $translations[$key] ?? $key;
    foreach ($params as $param => $value) {
        $translation = str_replace("{{$param}}", $value, $translation);
    }
    return $translation;
}

function debug_log($message, $data = null) {
    error_log(date('Y-m-d H:i:s') . " - " . $message);
    if ($data !== null) error_log(print_r($data, true));
}

function rot47_encrypt($string) {
    return strtr($string, 
        '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~',
        'PQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO'
    );
}

function rot47_decrypt($string) { 
    return rot47_encrypt($string); 
}

function remove_sensitive_columns_for_print($record, $rot47_columns) {
    $safe_record = [];
    foreach ($record as $field => $value) {
        if (in_array($field, $rot47_columns)) continue;
        $sensitive_patterns = ['email', 'telefoon', 'mobiel', 'contact', 'phone', 'tel', 'mobile'];
        $is_sensitive = false;
        foreach ($sensitive_patterns as $pattern) {
            if (stripos($field, $pattern) !== false) { 
                $is_sensitive = true; 
                break; 
            }
        }
        if (!$is_sensitive) $safe_record[$field] = $value;
    }
    return $safe_record;
}

function hash_password($password) { 
    return password_hash($password, PASSWORD_BCRYPT); 
}

function verify_password($password, $hash) { 
    return password_verify($password, $hash); 
}

function has_permission($permission) {
    global $current_user, $user_roles;
    if (!$current_user) return false;
    $role = $current_user['role'];
    return in_array($permission, $user_roles[$role]);
}

function get_ipv4_address() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if ($ip === '::1') return '127.0.0.1';
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if (strpos($ip, '::ffff:') === 0) return substr($ip, 7);
        if ($ip === '::1' || $ip === '0:0:0:0:0:0:0:1') return '127.0.0.1';
        $headers = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (isset($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                foreach ($ips as $client_ip) {
                    $client_ip = trim($client_ip);
                    if (filter_var($client_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return $client_ip;
                }
            }
        }
    }
    return $ip;
}

function create_users_table($connection, $table_name) {
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100),
        full_name VARCHAR(100),
        role ENUM('admin', 'editor', 'viewer') DEFAULT 'viewer',
        is_active BOOLEAN DEFAULT TRUE,
        last_login DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )";
    if ($connection->query($sql)) {
        $check_sql = "SELECT COUNT(*) as count FROM $table_name";
        $result = $connection->query($check_sql);
        $row = $result->fetch_assoc();
        if ($row['count'] == 0) {
            $default_password = hash_password('admin123');
            $insert_sql = "INSERT INTO $table_name (username, password, email, full_name, role) 
                          VALUES ('admin', '$default_password', 'admin@example.com', 'Administrator', 'admin')";
            $connection->query($insert_sql);
        }
        return true;
    }
    return false;
}

function create_changes_table($connection, $table_name) {
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id INT AUTO_INCREMENT PRIMARY KEY,
        table_name VARCHAR(100) NOT NULL,
        record_id INT NOT NULL,
        action ENUM('INSERT', 'UPDATE', 'DELETE') NOT NULL,
        old_data JSON,
        new_data JSON,
        changed_fields TEXT,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        changed_by INT NOT NULL,
        user_ip VARCHAR(45),
        user_agent VARCHAR(255),
        FOREIGN KEY (changed_by) REFERENCES system_users(id) ON DELETE CASCADE
    )";
    return $connection->query($sql);
}

function create_dpia_table($connection, $table_name) {
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id INT AUTO_INCREMENT PRIMARY KEY,
        record_id INT NOT NULL,
        description TEXT,
        necessity_proportionality TEXT,
        mitigation_measures TEXT,
        residual_risk TEXT,
        overall_risk_level ENUM('low', 'medium', 'high') DEFAULT 'medium',
        status ENUM('open', 'closed', 'pending') DEFAULT 'pending',
        registered_by INT NOT NULL,
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        notes TEXT,
        FOREIGN KEY (registered_by) REFERENCES system_users(id) ON DELETE CASCADE,
        FOREIGN KEY (record_id) REFERENCES avg_register(id) ON DELETE CASCADE,
        UNIQUE KEY unique_record_dpia (record_id)
    )";
    return $connection->query($sql);
}

function create_mfa_table($connection, $table_name) {
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        secret_key VARCHAR(64) NOT NULL,
        is_enabled BOOLEAN DEFAULT FALSE,
        backup_codes JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES system_users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_mfa (user_id)
    )";
    return $connection->query($sql);
}

function log_change($connection, $table_name, $record_id, $action, $old_data = null, $new_data = null, $changed_fields = null) {
    global $current_user, $db_config;
    $table = $db_config['changes_table'];
    $old_data_json = $old_data ? json_encode($old_data, JSON_UNESCAPED_UNICODE) : null;
    $new_data_json = $new_data ? json_encode($new_data, JSON_UNESCAPED_UNICODE) : null;
    $user_ip = get_ipv4_address();
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $sql = "INSERT INTO $table (table_name, record_id, action, old_data, new_data, changed_fields, changed_by, user_ip, user_agent) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("sissssiss", $table_name, $record_id, $action, $old_data_json, $new_data_json, $changed_fields, $current_user['id'], $user_ip, $user_agent);
        return $stmt->execute();
    }
    return false;
}

function get_changed_fields($old_data, $new_data) {
    $changed = [];
    $all_keys = array_unique(array_merge(array_keys($old_data), array_keys($new_data)));
    foreach ($all_keys as $key) {
        $old_value = $old_data[$key] ?? null;
        $new_value = $new_data[$key] ?? null;
        if ($old_value !== $new_value) $changed[] = $key;
    }
    return implode(', ', $changed);
}

function get_action_name($action) {
    $actions = ['INSERT' => 'Added', 'UPDATE' => 'Modified', 'DELETE' => 'Deleted'];
    return $actions[$action] ?? $action;
}

function getTableColumns($connection, $table) {
    $columns = [];
    $result = $connection->query("SHOW COLUMNS FROM $table");
    if ($result) while ($row = $result->fetch_assoc()) $columns[] = $row;
    return $columns;
}

function validateColumnExists($connection, $table, $column) {
    $columns = getTableColumns($connection, $table);
    foreach ($columns as $col) if ($col['Field'] === $column) return true;
    return false;
}

function has_dpia($connection, $record_id) {
    global $db_config;
    $sql = "SELECT COUNT(*) as count FROM {$db_config['dpia_table']} WHERE record_id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $record_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        return $row['count'] > 0;
    }
    return false;
}

function get_dpia_info($connection, $dpia_id) {
    global $db_config;
    $sql = "SELECT d.*, u.username, u.full_name, r.verwerkingsactiviteit, r.organisatorische_maatregelen, r.technische_maatregelen
            FROM {$db_config['dpia_table']} d 
            LEFT JOIN {$db_config['users_table']} u ON d.registered_by = u.id 
            LEFT JOIN {$db_config['table']} r ON d.record_id = r.id 
            WHERE d.id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $dpia_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
    return null;
}

function get_dpia_info_by_record($connection, $record_id) {
    global $db_config;
    $sql = "SELECT d.*, u.username, u.full_name, r.verwerkingsactiviteit, r.organisatorische_maatregelen, r.technische_maatregelen
            FROM {$db_config['dpia_table']} d 
            LEFT JOIN {$db_config['users_table']} u ON d.registered_by = u.id 
            LEFT JOIN {$db_config['table']} r ON d.record_id = r.id 
            WHERE d.record_id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $record_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
    return null;
}

function get_all_dpias($connection, $status = null) {
    global $db_config;
    $sql = "SELECT d.*, u.username, u.full_name, r.verwerkingsactiviteit 
            FROM {$db_config['dpia_table']} d 
            LEFT JOIN {$db_config['users_table']} u ON d.registered_by = u.id 
            LEFT JOIN {$db_config['table']} r ON d.record_id = r.id";
    if ($status) {
        $sql .= " WHERE d.status = ?";
        $stmt = $connection->prepare($sql);
        if ($stmt) {
            $stmt->bind_param("s", $status);
            $stmt->execute();
            $result = $stmt->get_result();
            $dpias = [];
            while ($row = $result->fetch_assoc()) $dpias[] = $row;
            return $dpias;
        }
    } else {
        $result = $connection->query($sql);
        $dpias = [];
        if ($result) while ($row = $result->fetch_assoc()) $dpias[] = $row;
        return $dpias;
    }
    return [];
}

function register_dpia($connection, $record_id, $data) {
    global $current_user, $db_config;
    if (has_dpia($connection, $record_id)) { 
        debug_log("DPIA already exists for record: $record_id"); 
        return false; 
    }
    debug_log("Attempting to register DPIA for record: $record_id", $data);
    debug_log("Current user ID: " . $current_user['id']);
    $sql = "INSERT INTO {$db_config['dpia_table']} (record_id, description, necessity_proportionality, mitigation_measures, residual_risk, overall_risk_level, status, registered_by, notes) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    debug_log("SQL query: $sql");
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("issssssis", $record_id, $data['description'], $data['necessity_proportionality'], $data['mitigation_measures'], $data['residual_risk'], $data['overall_risk_level'], $data['status'], $current_user['id'], $data['notes']);
        $result = $stmt->execute();
        if ($result) {
            debug_log("DPIA registration SUCCESS for record: $record_id, ID: " . $connection->insert_id);
            $new_data = ['record_id' => $record_id, 'description' => $data['description'], 'status' => $data['status'], 'overall_risk_level' => $data['overall_risk_level']];
            log_change($connection, $db_config['dpia_table'], $connection->insert_id, 'INSERT', null, $new_data, 'record_id,description,status,overall_risk_level');
        } else debug_log("DPIA registration FAILED for record: $record_id, Error: " . $stmt->error);
        return $result;
    } else { 
        debug_log("DPIA prepare failed for record: $record_id, Error: " . $connection->error); 
        return false; 
    }
}

function update_dpia($connection, $dpia_id, $data) {
    global $db_config;
    debug_log("Updating DPIA: $dpia_id", $data);
    $old_sql = "SELECT * FROM {$db_config['dpia_table']} WHERE id = ?";
    $old_stmt = $connection->prepare($old_sql);
    $old_stmt->bind_param("i", $dpia_id);
    $old_stmt->execute();
    $old_result = $old_stmt->get_result();
    $old_data = $old_result->fetch_assoc();
    $sql = "UPDATE {$db_config['dpia_table']} SET 
            description = ?,
            necessity_proportionality = ?,
            mitigation_measures = ?,
            residual_risk = ?,
            overall_risk_level = ?,
            status = ?,
            notes = ?,
            updated_at = CURRENT_TIMESTAMP
            WHERE id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("sssssssi", $data['description'], $data['necessity_proportionality'], $data['mitigation_measures'], $data['residual_risk'], $data['overall_risk_level'], $data['status'], $data['notes'], $dpia_id);
        $result = $stmt->execute();
        if ($result) {
            $new_data = ['description' => $data['description'], 'status' => $data['status'], 'overall_risk_level' => $data['overall_risk_level']];
            $changed_fields = get_changed_fields($old_data, $new_data);
            log_change($connection, $db_config['dpia_table'], $dpia_id, 'UPDATE', $old_data, $new_data, $changed_fields);
            debug_log("DPIA update SUCCESS for ID: $dpia_id");
        } else debug_log("DPIA update FAILED for ID: $dpia_id, Error: " . $stmt->error);
        return $result;
    }
    debug_log("DPIA prepare failed for update: " . $connection->error);
    return false;
}

function remove_dpia($connection, $record_id) {
    global $db_config;
    debug_log("Removing DPIA for record: $record_id");
    $old_sql = "SELECT * FROM {$db_config['dpia_table']} WHERE record_id = ?";
    $old_stmt = $connection->prepare($old_sql);
    $old_stmt->bind_param("i", $record_id);
    $old_stmt->execute();
    $old_result = $old_stmt->get_result();
    $old_data = $old_result->fetch_assoc();
    $sql = "DELETE FROM {$db_config['dpia_table']} WHERE record_id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $record_id);
        $result = $stmt->execute();
        if ($result) {
            log_change($connection, $db_config['dpia_table'], $record_id, 'DELETE', $old_data, null, 'all_fields');
            debug_log("DPIA removal SUCCESS for record: $record_id");
        } else debug_log("DPIA removal FAILED for record: $record_id, Error: " . $stmt->error);
        return $result;
    }
    return false;
}

function delete_dpia($connection, $dpia_id) {
    global $db_config;
    debug_log("Deleting DPIA ID: $dpia_id");
    $old_sql = "SELECT * FROM {$db_config['dpia_table']} WHERE id = ?";
    $old_stmt = $connection->prepare($old_sql);
    $old_stmt->bind_param("i", $dpia_id);
    $old_stmt->execute();
    $old_result = $old_stmt->get_result();
    $old_data = $old_result->fetch_assoc();
    $sql = "DELETE FROM {$db_config['dpia_table']} WHERE id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $dpia_id);
        $result = $stmt->execute();
        if ($result) {
            log_change($connection, $db_config['dpia_table'], $dpia_id, 'DELETE', $old_data, null, 'all_fields');
            debug_log("DPIA delete SUCCESS for ID: $dpia_id");
        } else debug_log("DPIA delete FAILED for ID: $dpia_id, Error: " . $stmt->error);
        return $result;
    }
    debug_log("DPIA delete prepare failed: " . $connection->error);
    return false;
}

function get_record_verwerkingsactiviteit($connection, $record_id) {
    global $db_config;
    $sql = "SELECT verwerkingsactiviteit FROM {$db_config['table']} WHERE id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $record_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        return $row['verwerkingsactiviteit'] ?? 'Unknown';
    }
    return 'Unknown';
}

function get_security_measures_from_record($connection, $record_id) {
    global $db_config;
    $sql = "SELECT organisatorische_maatregelen, technische_maatregelen FROM {$db_config['table']} WHERE id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $record_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $measures = [];
        if (!empty($row['organisatorische_maatregelen'])) $measures[] = "**" . t('organizational_measures') . ":**\n" . $row['organisatorische_maatregelen'];
        if (!empty($row['technische_maatregelen'])) $measures[] = "**" . t('technical_measures') . ":**\n" . $row['technische_maatregelen'];
        return implode("\n\n", $measures);
    }
    return '';
}

function get_full_record_details_for_print($connection, $record_id, $rot47_columns) {
    global $db_config;
    $sql = "SELECT * FROM {$db_config['table']} WHERE id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $record_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result && $row = $result->fetch_assoc()) {
            $safe_record = remove_sensitive_columns_for_print($row, $rot47_columns);
            $update_status = [];
            if (!empty($row['updated_at'])) {
                $days_since = floor((time() - strtotime($row['updated_at'])) / (60 * 60 * 24));
                $update_status['days_since'] = $days_since;
                $update_status['needs_update'] = $days_since > 180 ? 'Yes' : 'No';
                $update_status['last_updated'] = $row['updated_at'];
            } else {
                $update_status['days_since'] = 'N/A';
                $update_status['needs_update'] = 'Unknown';
                $update_status['last_updated'] = 'Never';
            }
            $dpia_info = get_dpia_info_by_record($connection, $record_id);
            return ['record' => $safe_record, 'update_status' => $update_status, 'dpia_info' => $dpia_info, 'has_dpia' => !empty($dpia_info), 'excluded_columns' => $rot47_columns];
        }
    }
    return null;
}

function get_all_records_with_dpia_for_print($connection, $rot47_columns, $only_with_dpia = false) {
    global $db_config;
    if ($only_with_dpia) {
        $sql = "SELECT v.*, d.id as dpia_id, d.description as dpia_description, 
                       d.necessity_proportionality, d.mitigation_measures, 
                       d.residual_risk, d.overall_risk_level, d.status as dpia_status,
                       d.registered_at as dpia_registered_at, d.updated_at as dpia_updated_at,
                       d.notes as dpia_notes, u.username as dpia_registered_by_username,
                       u.full_name as dpia_registered_by_name
                FROM {$db_config['table']} v
                INNER JOIN {$db_config['dpia_table']} d ON v.id = d.record_id
                LEFT JOIN {$db_config['users_table']} u ON d.registered_by = u.id
                ORDER BY v.id";
    } else {
        $sql = "SELECT v.*, d.id as dpia_id, d.description as dpia_description, 
                       d.necessity_proportionality, d.mitigation_measures, 
                       d.residual_risk, d.overall_risk_level, d.status as dpia_status,
                       d.registered_at as dpia_registered_at, d.updated_at as dpia_updated_at,
                       d.notes as dpia_notes, u.username as dpia_registered_by_username,
                       u.full_name as dpia_registered_by_name
                FROM {$db_config['table']} v
                LEFT JOIN {$db_config['dpia_table']} d ON v.id = d.record_id
                LEFT JOIN {$db_config['users_table']} u ON d.registered_by = u.id
                ORDER BY v.id";
    }
    $result = $connection->query($sql);
    $records = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $safe_record = remove_sensitive_columns_for_print($row, $rot47_columns);
            $update_status = [];
            if (!empty($row['updated_at'])) {
                $days_since = floor((time() - strtotime($row['updated_at'])) / (60 * 60 * 24));
                $update_status['days_since'] = $days_since;
                $update_status['needs_update'] = $days_since > 180 ? 'Yes' : 'No';
                $update_status['last_updated'] = $row['updated_at'];
            } else {
                $update_status['days_since'] = 'N/A';
                $update_status['needs_update'] = 'Unknown';
                $update_status['last_updated'] = 'Never';
            }
            $dpia_info = null;
            if (!empty($row['dpia_id'])) {
                $dpia_info = [
                    'id' => $row['dpia_id'],
                    'description' => $row['dpia_description'],
                    'necessity_proportionality' => $row['necessity_proportionality'],
                    'mitigation_measures' => $row['mitigation_measures'],
                    'residual_risk' => $row['residual_risk'],
                    'overall_risk_level' => $row['overall_risk_level'],
                    'status' => $row['dpia_status'],
                    'registered_at' => $row['dpia_registered_at'],
                    'updated_at' => $row['dpia_updated_at'],
                    'notes' => $row['dpia_notes'],
                    'registered_by_username' => $row['dpia_registered_by_username'],
                    'registered_by_name' => $row['dpia_registered_by_name']
                ];
            }
            $records[] = [
                'record' => $safe_record,
                'update_status' => $update_status,
                'dpia_info' => $dpia_info,
                'has_dpia' => !empty($row['dpia_id']),
                'excluded_columns' => $rot47_columns
            ];
        }
    }
    return $records;
}

function get_records_not_recently_updated($connection) {
    global $db_config, $recent_update_threshold;
    $sql = "SELECT id, verwerkingsactiviteit, updated_at, 
            DATEDIFF(CURDATE(), DATE(updated_at)) as days_since_update,
            organisatorische_maatregelen, technische_maatregelen
            FROM {$db_config['table']} 
            WHERE updated_at IS NOT NULL 
            AND DATEDIFF(CURDATE(), DATE(updated_at)) > ?
            ORDER BY days_since_update DESC 
            LIMIT 10";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $recent_update_threshold);
        $stmt->execute();
        $result = $stmt->get_result();
        $records = [];
        while ($row = $result->fetch_assoc()) $records[] = $row;
        return $records;
    }
    return [];
}

function get_count_records_not_recently_updated($connection) {
    global $db_config, $recent_update_threshold;
    $sql = "SELECT COUNT(*) as count 
            FROM {$db_config['table']} 
            WHERE updated_at IS NOT NULL 
            AND DATEDIFF(CURDATE(), DATE(updated_at)) > ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $recent_update_threshold);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        return $row['count'] ?? 0;
    }
    return 0;
}

function get_update_statistics($connection) {
    global $db_config, $recent_update_threshold;
    $stats = [
        'total_records' => 0, 'needs_update' => 0, 'up_to_date' => 0, 'average_days_since_update' => 0,
        'oldest_update' => null, 'newest_update' => null, 'update_distribution' => []
    ];
    $sql = "SELECT COUNT(*) as count FROM {$db_config['table']}";
    $result = $connection->query($sql);
    if ($result) { $row = $result->fetch_assoc(); $stats['total_records'] = $row['count'] ?? 0; }
    $sql = "SELECT COUNT(*) as count 
            FROM {$db_config['table']} 
            WHERE updated_at IS NOT NULL 
            AND DATEDIFF(CURDATE(), DATE(updated_at)) > ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $recent_update_threshold);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stats['needs_update'] = $row['count'] ?? 0;
    }
    $stats['up_to_date'] = $stats['total_records'] - $stats['needs_update'];
    $sql = "SELECT AVG(DATEDIFF(CURDATE(), DATE(updated_at))) as avg_days 
            FROM {$db_config['table']} 
            WHERE updated_at IS NOT NULL";
    $result = $connection->query($sql);
    if ($result) { $row = $result->fetch_assoc(); $stats['average_days_since_update'] = round($row['avg_days'] ?? 0, 1); }
    $sql = "SELECT MIN(updated_at) as oldest, MAX(updated_at) as newest 
            FROM {$db_config['table']} 
            WHERE updated_at IS NOT NULL";
    $result = $connection->query($sql);
    if ($result) { $row = $result->fetch_assoc(); $stats['oldest_update'] = $row['oldest'] ?? null; $stats['newest_update'] = $row['newest'] ?? null; }
    $sql = "SELECT 
                CASE 
                    WHEN DATEDIFF(CURDATE(), DATE(updated_at)) <= 30 THEN '0-30 days'
                    WHEN DATEDIFF(CURDATE(), DATE(updated_at)) <= 90 THEN '31-90 days'
                    WHEN DATEDIff(CURDATE(), DATE(updated_at)) <= 180 THEN '91-180 days'
                    WHEN DATEDIFF(CURDATE(), DATE(updated_at)) <= 365 THEN '181-365 days'
                    ELSE 'Over 1 year'
                END as timeframe,
                COUNT(*) as count
            FROM {$db_config['table']} 
            WHERE updated_at IS NOT NULL
            GROUP BY timeframe
            ORDER BY 
                CASE timeframe
                    WHEN '0-30 days' THEN 1
                    WHEN '31-90 days' THEN 2
                    WHEN '91-180 days' THEN 3
                    WHEN '181-365 days' THEN 4
                    ELSE 5
                END";
    $result = $connection->query($sql);
    if ($result) while ($row = $result->fetch_assoc()) $stats['update_distribution'][] = $row;
    return $stats;
}

function get_update_priority($days_since_update) {
    global $recent_update_threshold;
    if ($days_since_update > 365) return 'high';
    elseif ($days_since_update > $recent_update_threshold) return 'medium';
    elseif ($days_since_update > $recent_update_threshold / 2) return 'low';
    else return 'none';
}

function get_priority_color($priority) {
    switch ($priority) {
        case 'high': return '#f44336';
        case 'medium': return '#ff9800';
        case 'low': return '#ffc107';
        default: return '#4CAF50';
    }
}

function get_compact_table_data_updated($connection, $records, $rot47_columns) {
    global $recent_update_threshold;
    $compact_data = [];
    foreach ($records as $record) {
        $row = [];
        $compact_columns = ['id', 'verwerkingsactiviteit', 'avg_registersovereenkomstmetderdepartij', 'wijzijnverwerker'];
        foreach ($compact_columns as $col_name) {
            if (isset($record[$col_name])) {
                $value = $record[$col_name];
                if (in_array($col_name, $rot47_columns) && $value !== null && $value !== '') {
                    $value = rot47_decrypt($value);
                }
                $row[$col_name] = $value;
            } else {
                $row[$col_name] = '';
            }
        }
        
        $dpia_vereist = isset($record['dpia_vereist']) ? $record['dpia_vereist'] : 'Nee';
        $row['dpia_vereist'] = $dpia_vereist;
        
        $has_dpia = has_dpia($connection, $record['id']);
        $row['dpia_registered'] = $has_dpia ? 'Ja' : 'Nee';
        
        $update_needed = 'No';
        $days_since = 'N/A';
        if (!empty($record['updated_at'])) {
            $days_since = floor((time() - strtotime($record['updated_at'])) / (60 * 60 * 24));
            $update_needed = $days_since > $recent_update_threshold ? 'Yes' : 'No';
        } elseif (!empty($record['created_at'])) {
            $days_since = floor((time() - strtotime($record['created_at'])) / (60 * 60 * 24));
            $update_needed = $days_since > $recent_update_threshold ? 'Yes' : 'No';
        }
        $row['days_since_update'] = $days_since;
        $row['update_needed'] = $update_needed;
        $compact_data[] = $row;
    }
    return $compact_data;
}

// MFA Functions
function generate_secret_key($length = 32) {
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 characters
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $characters[random_int(0, strlen($characters) - 1)];
    }
    return $secret;
}

function generate_backup_codes($count = 8) {
    $codes = [];
    for ($i = 0; $i < $count; $i++) {
        $codes[] = strtoupper(substr(md5(uniqid(mt_rand(), true)), 0, 10));
    }
    return $codes;
}

function get_mfa_info($connection, $user_id) {
    global $db_config;
    $sql = "SELECT * FROM {$db_config['mfa_table']} WHERE user_id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
    return null;
}

function enable_mfa($connection, $user_id, $secret_key) {
    global $db_config, $current_user;
    $backup_codes = json_encode(generate_backup_codes());
    
    // Store secret key WITHOUT encryption
    $sql = "INSERT INTO {$db_config['mfa_table']} (user_id, secret_key, is_enabled, backup_codes) 
            VALUES (?, ?, TRUE, ?)
            ON DUPLICATE KEY UPDATE 
            secret_key = VALUES(secret_key), 
            is_enabled = VALUES(is_enabled),
            backup_codes = VALUES(backup_codes)";
    
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("iss", $user_id, $secret_key, $backup_codes);
        $result = $stmt->execute();
        
        if ($result) {
            log_change($connection, $db_config['mfa_table'], $user_id, 'UPDATE', null, [
                'user_id' => $user_id, 
                'is_enabled' => true,
                'action' => 'MFA enabled'
            ], 'user_id,is_enabled');
        }
        return $result;
    }
    return false;
}

function disable_mfa($connection, $user_id) {
    global $db_config, $current_user;
    $sql = "UPDATE {$db_config['mfa_table']} SET is_enabled = FALSE WHERE user_id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $result = $stmt->execute();
        if ($result) {
            log_change($connection, $db_config['mfa_table'], $user_id, 'UPDATE', null, [
                'user_id' => $user_id, 
                'is_enabled' => false,
                'action' => 'MFA disabled'
            ], 'user_id,is_enabled');
        }
        return $result;
    }
    return false;
}

function regenerate_backup_codes($connection, $user_id) {
    global $db_config;
    $backup_codes = json_encode(generate_backup_codes());
    $sql = "UPDATE {$db_config['mfa_table']} SET backup_codes = ? WHERE user_id = ?";
    $stmt = $connection->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("si", $backup_codes, $user_id);
        return $stmt->execute();
    }
    return false;
}

function base32_decode($secret) {
    $secret = strtoupper($secret);
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $buffer = 0;
    $bufferSize = 0;
    $result = '';
    
    for ($i = 0; $i < strlen($secret); $i++) {
        $char = $secret[$i];
        if ($char === ' ') continue;
        $val = strpos($chars, $char);
        if ($val === false) return false;
        $buffer <<= 5;
        $buffer |= $val;
        $bufferSize += 5;
        if ($bufferSize >= 8) {
            $bufferSize -= 8;
            $result .= chr(($buffer >> $bufferSize) & 0xFF);
        }
    }
    return $result;
}

function verify_totp_code($secret, $code) {
    $time = floor(time() / 30);
    $key = base32_decode($secret);
    
    if (!$key) return false;
    
    for ($i = -1; $i <= 1; $i++) {
        $hash = hash_hmac('sha1', pack('J', $time + $i), $key, true);
        $offset = ord($hash[19]) & 0xf;
        $result = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % pow(10, 6);
        
        if (str_pad($result, 6, '0', STR_PAD_LEFT) === $code) {
            return true;
        }
    }
    return false;
}

function verify_backup_code($connection, $user_id, $code) {
    global $db_config;
    $mfa_info = get_mfa_info($connection, $user_id);
    if (!$mfa_info || empty($mfa_info['backup_codes'])) return false;
    
    $backup_codes = json_decode($mfa_info['backup_codes'], true);
    if (!is_array($backup_codes)) return false;
    
    $code = strtoupper(trim($code));
    $index = array_search($code, $backup_codes);
    
    if ($index !== false) {
        unset($backup_codes[$index]);
        $backup_codes = array_values($backup_codes);
        
        $sql = "UPDATE {$db_config['mfa_table']} SET backup_codes = ? WHERE user_id = ?";
        $stmt = $connection->prepare($sql);
        if ($stmt) {
            $stmt->bind_param("si", json_encode($backup_codes), $user_id);
            $stmt->execute();
        }
        return true;
    }
    
    return false;
}

function get_user_mfa_status($connection, $user_id) {
    $mfa_info = get_mfa_info($connection, $user_id);
    if (!$mfa_info) {
        return [
            'enabled' => false,
            'has_secret' => false,
            'has_backup_codes' => false
        ];
    }
    
    return [
        'enabled' => (bool)$mfa_info['is_enabled'],
        'has_secret' => !empty($mfa_info['secret_key']),
        'has_backup_codes' => !empty($mfa_info['backup_codes']),
        'last_updated' => $mfa_info['updated_at']
    ];
}

function force_enable_mfa($connection, $user_id, $admin_id) {
    global $db_config;
    $secret_key = generate_secret_key();
    $result = enable_mfa($connection, $user_id, $secret_key);
    
    if ($result) {
        log_change($connection, $db_config['mfa_table'], $user_id, 'UPDATE', null, [
            'user_id' => $user_id,
            'action' => 'MFA force-enabled by admin',
            'admin_id' => $admin_id
        ], 'user_id,action,admin_id');
    }
    
    return $result;
}

function force_disable_mfa($connection, $user_id, $admin_id) {
    global $db_config;
    $result = disable_mfa($connection, $user_id);
    
    if ($result) {
        log_change($connection, $db_config['mfa_table'], $user_id, 'UPDATE', null, [
            'user_id' => $user_id,
            'action' => 'MFA force-disabled by admin',
            'admin_id' => $admin_id
        ], 'user_id,action,admin_id');
    }
    
    return $result;
}

function check_mfa_required($connection, $user_id) {
    $mfa_info = get_mfa_info($connection, $user_id);
    return $mfa_info && $mfa_info['is_enabled'];
}

// Initialize variables
$connection = null; $error = ''; $success = ''; $result = null; $columns = []; $edit_row = null;
$sort_column = ''; $sort_direction = 'ASC'; $is_logged_in = false; $current_user = null; $changes = [];
$show_changes = false; $total_rows = 0; $show_user_form = false; $view_mode = 'table';
$show_dpia_list = isset($_GET['view_dpias']) ? true : false; $dpia_status_filter = isset($_GET['dpia_status']) ? $_GET['dpia_status'] : null;
$edit_dpia_id = isset($_GET['edit_dpia']) ? intval($_GET['edit_dpia']) : 0; $add_dpia_record = isset($_GET['add_dpia']) ? intval($_GET['add_dpia']) : 0;
$view_dpia_id = isset($_GET['view_dpia']) ? intval($_GET['view_dpia']) : 0; $dpias = []; $all_dpias_count = 0; $open_dpias_count = 0;
$closed_dpias_count = 0; $pending_dpias_count = 0; $records_to_update = []; $count_records_to_update = 0; $update_statistics = [];
$print_individual = isset($_GET['print_record']) ? intval($_GET['print_record']) : 0; $print_compact = isset($_GET['print_compact']) ? true : false;
$print_full_details = isset($_GET['print_full']) ? true : false; $print_all_with_dpia = isset($_GET['print_all_with_dpia']) ? true : false;
$only_with_dpia = isset($_GET['only_with_dpia']) ? true : false; $watermark = true; $full_record_details = null; $batch_records = [];
$show_mfa_setup = false; $mfa_required = false; $show_mfa_admin = false; $user_mfa_statuses = [];

// Check session status
if (isset($_SESSION['mfa_verified']) && $_SESSION['mfa_verified'] === true) {
    $is_logged_in = true;
    $current_user = $_SESSION['user'];
} elseif (isset($_SESSION['user_id']) && isset($_SESSION['user'])) {
    $temp_connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
    if (!$temp_connection->connect_error) {
        create_mfa_table($temp_connection, $db_config['mfa_table']);
        $mfa_info = get_mfa_info($temp_connection, $_SESSION['user_id']);
        if ($mfa_info && $mfa_info['is_enabled']) {
            $mfa_required = true;
            $current_user = $_SESSION['user'];
        } else {
            $is_logged_in = true;
            $current_user = $_SESSION['user'];
        }
        $temp_connection->close();
    }
}

// Handle GET parameters
if (isset($_GET['setup_mfa'])) {
    $show_mfa_setup = true;
}

if (isset($_GET['mfa_admin'])) {
    if ($is_logged_in && has_permission('manage_mfa')) {
        $show_mfa_admin = true;
    }
}

// Setup database tables
try {
    $setup_connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
    if ($setup_connection->connect_error) throw new Exception("Connection failed: " . $setup_connection->connect_error);
    create_users_table($setup_connection, $db_config['users_table']);
    create_changes_table($setup_connection, $db_config['changes_table']);
    create_dpia_table($setup_connection, $db_config['dpia_table']);
    create_mfa_table($setup_connection, $db_config['mfa_table']);
    $setup_connection->close();
} catch (Exception $e) {}

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // MFA Verification
    if (isset($_POST['action']) && $_POST['action'] === 'verify_mfa') {
        try {
            $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
            if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
            
            $user_id = $_SESSION['user_id'];
            $code = trim($_POST['mfa_code'] ?? '');
            $backup_code = isset($_POST['backup_code']) ? trim($_POST['backup_code']) : '';
            
            $mfa_info = get_mfa_info($connection, $user_id);
            
            if (!$mfa_info || !$mfa_info['is_enabled']) {
                $error = t('mfa_not_setup');
            } elseif (!empty($backup_code)) {
                if (verify_backup_code($connection, $user_id, $backup_code)) {
                    $_SESSION['mfa_verified'] = true;
                    $success = t('login_successful');
                    header("Location: ?");
                    exit();
                } else {
                    $error = t('invalid_backup_code');
                }
            } elseif (!empty($code)) {
                if (verify_totp_code($mfa_info['secret_key'], $code)) {
                    $_SESSION['mfa_verified'] = true;
                    $success = t('login_successful');
                    header("Location: ?");
                    exit();
                } else {
                    $error = t('mfa_invalid_code');
                }
            } else {
                $error = t('enter_mfa_code');
            }
            
            $connection->close();
        } catch (Exception $e) { $error = $e->getMessage(); }
    }
    // MFA Setup
    elseif (isset($_POST['action']) && $_POST['action'] === 'setup_mfa') {
        try {
            $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
            if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
            
            $user_id = $_SESSION['user_id'];
            $code = trim($_POST['mfa_code'] ?? '');
            $secret_key = $_POST['secret_key'] ?? '';
            
            if (empty($secret_key)) {
                $error = "Invalid secret key";
            } elseif (verify_totp_code($secret_key, $code)) {
                if (enable_mfa($connection, $user_id, $secret_key)) {
                    $_SESSION['mfa_verified'] = true;
                    $success = t('mfa_enabled_success');
                    $show_mfa_setup = false;
                    header("Location: ?");
                    exit();
                } else {
                    $error = "Failed to enable MFA";
                }
            } else {
                $error = t('mfa_invalid_code');
            }
            
            $connection->close();
        } catch (Exception $e) { $error = $e->getMessage(); }
    }
    // MFA Admin Actions
    elseif (isset($_POST['mfa_admin_action'])) {
        if ($is_logged_in && has_permission('manage_mfa')) {
            try {
                $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
                if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
                
                $user_id = intval($_POST['user_id']);
                $admin_id = $current_user['id'];
                
                switch ($_POST['mfa_admin_action']) {
                    case 'force_enable':
                        if (force_enable_mfa($connection, $user_id, $admin_id)) {
                            $success = t('mfa_forced_enabled');
                        } else {
                            $error = "Failed to force enable MFA";
                        }
                        break;
                    case 'force_disable':
                        if (force_disable_mfa($connection, $user_id, $admin_id)) {
                            $success = t('mfa_forced_disabled');
                        } else {
                            $error = "Failed to force disable MFA";
                        }
                        break;
                }
                
                $connection->close();
                header("Location: ?mfa_admin=1");
                exit();
            } catch (Exception $e) { $error = $e->getMessage(); }
        }
    }
    // Login
    elseif (isset($_POST['action']) && $_POST['action'] === 'login') {
        try {
            $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
            if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
            
            $username = $connection->real_escape_string($_POST['username']);
            $password = $_POST['password'];
            $sql = "SELECT * FROM {$db_config['users_table']} WHERE username = '$username' AND is_active = TRUE";
            $result = $connection->query($sql);
            
            if ($result && $result->num_rows > 0) {
                $user = $result->fetch_assoc();
                if (verify_password($password, $user['password'])) {
                    $update_sql = "UPDATE {$db_config['users_table']} SET last_login = NOW() WHERE id = {$user['id']}";
                    $connection->query($update_sql);
                    
                    $mfa_info = get_mfa_info($connection, $user['id']);
                    
                    if ($mfa_info && $mfa_info['is_enabled']) {
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['user'] = $user;
                        $current_user = $user;
                        $mfa_required = true;
                        $success = t('mfa_required');
                    } else {
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['user'] = $user;
                        $_SESSION['mfa_verified'] = true;
                        $is_logged_in = true;
                        $current_user = $user;
                        $success = t('login_successful');
                        header("Location: ?");
                        exit();
                    }
                } else {
                    $error = t('invalid_password');
                }
            } else {
                $error = t('invalid_password');
            }
            $connection->close();
        } catch (Exception $e) { $error = $e->getMessage(); }
    }
    // Logout
    elseif (isset($_POST['action']) && $_POST['action'] === 'logout') { 
        session_destroy(); 
        header("Location: ?"); 
        exit(); 
    }
    // Other actions
    elseif (isset($_POST['action']) && $_POST['action'] === 'show_changes') $show_changes = true;
    elseif (isset($_POST['action']) && $_POST['action'] === 'show_user_form') $show_user_form = true;
    elseif (isset($_POST['action']) && $_POST['action'] === 'show_dpias') $show_dpia_list = true;
    elseif ($is_logged_in && has_permission('manage_users')) {
        try {
            $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
            if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
            if (isset($_POST['user_action'])) {
                switch ($_POST['user_action']) {
                    case 'add_user':
                        $username = $connection->real_escape_string($_POST['username']);
                        $password = hash_password($_POST['password']);
                        $email = $connection->real_escape_string($_POST['email']);
                        $full_name = $connection->real_escape_string($_POST['full_name']);
                        $role = $connection->real_escape_string($_POST['role']);
                        $sql = "INSERT INTO {$db_config['users_table']} (username, password, email, full_name, role) 
                                VALUES ('$username', '$password', '$email', '$full_name', '$role')";
                        if ($connection->query($sql)) {
                            $user_id = $connection->insert_id;
                            log_change($connection, $db_config['users_table'], $user_id, 'INSERT', null, [
                                'username' => $username, 'email' => $email, 'full_name' => $full_name, 'role' => $role
                            ], 'username,email,full_name,role');
                            $success = t('operation_completed');
                            $show_user_form = false;
                        } else { $error = "Error adding user: " . $connection->error; $show_user_form = true; }
                        break;
                    case 'edit_user':
                        $user_id = $connection->real_escape_string($_POST['user_id']);
                        $email = $connection->real_escape_string($_POST['email']);
                        $full_name = $connection->real_escape_string($_POST['full_name']);
                        $role = $connection->real_escape_string($_POST['role']);
                        $is_active = isset($_POST['is_active']) ? 1 : 0;
                        $old_sql = "SELECT email, full_name, role, is_active FROM {$db_config['users_table']} WHERE id = '$user_id'";
                        $old_result = $connection->query($old_sql);
                        $old_data = $old_result->fetch_assoc();
                        $sql = "UPDATE {$db_config['users_table']} SET 
                                email = '$email', 
                                full_name = '$full_name', 
                                role = '$role',
                                is_active = $is_active,
                                updated_at = CURRENT_TIMESTAMP
                                WHERE id = '$user_id'";
                        if ($connection->query($sql)) {
                            $new_data = ['email' => $email, 'full_name' => $full_name, 'role' => $role, 'is_active' => $is_active];
                            $changed_fields = get_changed_fields($old_data, $new_data);
                            log_change($connection, $db_config['users_table'], $user_id, 'UPDATE', $old_data, $new_data, $changed_fields);
                            $success = t('operation_completed');
                        } else $error = "Error updating user: " . $connection->error;
                        break;
                    case 'delete_user':
                        $user_id = $connection->real_escape_string($_POST['user_id']);
                        if ($user_id == $current_user['id']) $error = t('cannot_delete_self');
                        else {
                            $old_sql = "SELECT username, email, full_name, role FROM {$db_config['users_table']} WHERE id = '$user_id'";
                            $old_result = $connection->query($old_sql);
                            $old_data = $old_result->fetch_assoc();
                            $sql = "DELETE FROM {$db_config['users_table']} WHERE id = '$user_id'";
                            if ($connection->query($sql)) {
                                log_change($connection, $db_config['users_table'], $user_id, 'DELETE', $old_data, null, 'username,email,full_name,role');
                                $success = t('item_deleted');
                            } else $error = "Error deleting user: " . $connection->error;
                        }
                        break;
                }
            }
            $connection->close();
        } catch (Exception $e) { $error = $e->getMessage(); }
    }
}

// Handle DPIA actions
if ($is_logged_in && isset($_POST['dpia_action'])) {
    debug_log("DPIA action detected: " . $_POST['dpia_action']);
    try {
        $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
        if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
        switch ($_POST['dpia_action']) {
            case 'add_dpia':
                debug_log("Processing add_dpia action");
                if (!has_permission('manage_dpia')) { $error = t('no_permission_view'); debug_log("User doesn't have permission to add DPIA"); break; }
                $record_id = intval($_POST['record_id']);
                debug_log("Record ID from form: $record_id");
                $data = [
                    'description' => trim($_POST['description'] ?? ''),
                    'necessity_proportionality' => trim($_POST['necessity_proportionality'] ?? ''),
                    'mitigation_measures' => trim($_POST['mitigation_measures'] ?? ''),
                    'residual_risk' => trim($_POST['residual_risk'] ?? ''),
                    'overall_risk_level' => $_POST['overall_risk_level'] ?? 'medium',
                    'status' => $_POST['status'] ?? 'pending',
                    'notes' => trim($_POST['notes'] ?? '')
                ];
                debug_log("DPIA form data received", $data);
                $required_fields = ['description', 'necessity_proportionality', 'mitigation_measures', 'residual_risk'];
                $missing_fields = [];
                foreach ($required_fields as $field) if (empty($data[$field])) $missing_fields[] = $field;
                if (!empty($missing_fields)) { $error = "Please fill in all required fields: " . implode(', ', $missing_fields); debug_log("Missing required fields: " . implode(', ', $missing_fields)); break; }
                if (register_dpia($connection, $record_id, $data)) {
                    $success = t('dpia_registration_success');
                    debug_log("DPIA registration successful, redirecting...");
                    $connection->close();
                    header("Location: ?view_dpias=1");
                    exit();
                } else { $error = t('dpia_already_registered') . " or database error"; debug_log("DPIA registration failed"); }
                break;
            case 'edit_dpia':
                debug_log("Processing edit_dpia action");
                if (!has_permission('manage_dpia')) { $error = t('no_permission_view'); debug_log("User doesn't have permission to edit DPIA"); break; }
                $dpia_id = intval($_POST['dpia_id']);
                debug_log("DPIA ID from form: $dpia_id");
                $data = [
                    'description' => trim($_POST['description'] ?? ''),
                    'necessity_proportionality' => trim($_POST['necessity_proportionality'] ?? ''),
                    'mitigation_measures' => trim($_POST['mitigation_measures'] ?? ''),
                    'residual_risk' => trim($_POST['residual_risk'] ?? ''),
                    'overall_risk_level' => $_POST['overall_risk_level'] ?? 'medium',
                    'status' => $_POST['status'] ?? 'pending',
                    'notes' => trim($_POST['notes'] ?? '')
                ];
                debug_log("DPIA edit data received", $data);
                $required_fields = ['description', 'necessity_proportionality', 'mitigation_measures', 'residual_risk'];
                $missing_fields = [];
                foreach ($required_fields as $field) if (empty($data[$field])) $missing_fields[] = $field;
                if (!empty($missing_fields)) { $error = "Please fill in all required fields: " . implode(', ', $missing_fields); debug_log("Missing required fields: " . implode(', ', $missing_fields)); break; }
                if (update_dpia($connection, $dpia_id, $data)) {
                    $success = t('operation_completed');
                    debug_log("DPIA update successful, redirecting...");
                    $connection->close();
                    header("Location: ?view_dpia=" . $dpia_id);
                    exit();
                } else { $error = "Error updating DPIA"; debug_log("DPIA update failed"); }
                break;
            case 'remove_dpia':
                debug_log("Processing remove_dpia action");
                if (!has_permission('manage_dpia')) { $error = t('no_permission_view'); break; }
                $record_id = intval($_POST['record_id']);
                debug_log("Removing DPIA for record ID: $record_id");
                if (remove_dpia($connection, $record_id)) {
                    $success = t('dpia_removed');
                    debug_log("DPIA removal successful, redirecting...");
                    $connection->close();
                    header("Location: ?");
                    exit();
                } else { $error = "Error removing DPIA"; debug_log("DPIA removal failed"); }
                break;
            case 'delete_dpia':
                debug_log("Processing delete_dpia action");
                if (!has_permission('manage_dpia')) { $error = t('no_permission_view'); break; }
                $dpia_id = intval($_POST['dpia_id']);
                debug_log("Deleting DPIA ID: $dpia_id");
                if (delete_dpia($connection, $dpia_id)) {
                    $success = t('item_deleted');
                    debug_log("DPIA delete successful, redirecting...");
                    $connection->close();
                    header("Location: ?view_dpias=1");
                    exit();
                } else { $error = "Error deleting DPIA"; debug_log("DPIA delete failed"); }
                break;
        }
        $connection->close();
    } catch (Exception $e) { $error = $e->getMessage(); debug_log("Exception in DPIA handling: " . $e->getMessage()); }
}

// Handle other POST actions (add, edit, delete records)
if ($is_logged_in && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action']) && in_array($_POST['action'], ['add', 'edit', 'delete'])) {
        try {
            $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
            if ($connection->connect_error) throw new Exception("Connection failed: " . $connection->connect_error);
            switch ($_POST['action']) {
                case 'add':
                    if (!has_permission('add')) { $error = "You don't have permission to add records"; break; }
                    $columns = getTableColumns($connection, $db_config['table']);
                    $values = []; $new_data = [];
                    foreach ($columns as $col) {
                        $col_name = $col['Field'];
                        if ($col_name === 'id' || strpos($col['Extra'], 'auto_increment') !== false) continue;
                        if ($col_name === 'created_at' || $col_name === 'updated_at') continue;
                        if (isset($_POST[$col_name])) {
                            $value = trim($_POST[$col_name]);
                            if (in_array($col_name, $rot47_columns) && $value !== '') $value = rot47_encrypt($value);
                            $value = $connection->real_escape_string($value);
                            $values[$col_name] = "'$value'";
                            $new_data[$col_name] = $value;
                        } else { $values[$col_name] = "NULL"; $new_data[$col_name] = null; }
                    }
                    if (!empty($values)) {
                        $columns_str = implode(', ', array_keys($values));
                        $values_str = implode(', ', array_values($values));
                        $sql = "INSERT INTO {$db_config['table']} ($columns_str) VALUES ($values_str)";
                        if ($connection->query($sql)) {
                            $record_id = $connection->insert_id;
                            $new_data['created_at'] = date('Y-m-d H:i:s');
                            $new_data['updated_at'] = date('Y-m-d H:i:s');
                            log_change($connection, $db_config['table'], $record_id, 'INSERT', null, $new_data, $columns_str);
                            $success = t('operation_completed');
                        } else $error = "Error adding record: " . $connection->error;
                    }
                    break;
                case 'edit':
                    if (!has_permission('edit')) { $error = "You don't have permission to edit records"; break; }
                    if (isset($_POST['id'])) {
                        $edit_id = $connection->real_escape_string($_POST['id']);
                        $columns = getTableColumns($connection, $db_config['table']);
                        $updates = []; $new_data = [];
                        $old_sql = "SELECT * FROM {$db_config['table']} WHERE id = '$edit_id' LIMIT 1";
                        $old_result = $connection->query($old_sql);
                        $old_data = $old_result->fetch_assoc();
                        foreach ($columns as $col) {
                            $col_name = $col['Field'];
                            if ($col_name === 'id' || strpos($col['Extra'], 'auto_increment') !== false) continue;
                            if ($col_name === 'created_at' || $col_name === 'updated_at') continue;
                            if (isset($_POST[$col_name])) {
                                $value = trim($_POST[$col_name]);
                                $log_value = $value;
                                if (in_array($col_name, $rot47_columns) && $value !== '') $value = rot47_encrypt($value);
                                $value = $connection->real_escape_string($value);
                                $updates[] = "$col_name = '$value'";
                                $new_data[$col_name] = $log_value;
                            }
                        }
                        $updates[] = "updated_at = CURRENT_TIMESTAMP";
                        if (!empty($updates)) {
                            $updates_str = implode(', ', $updates);
                            $sql = "UPDATE {$db_config['table']} SET $updates_str WHERE id = '$edit_id'";
                            if ($connection->query($sql)) {
                                $new_data['updated_at'] = date('Y-m-d H:i:s');
                                $changed_fields = get_changed_fields($old_data, $new_data);
                                $changed_fields .= ($changed_fields ? ', ' : '') . 'updated_at';
                                log_change($connection, $db_config['table'], $edit_id, 'UPDATE', $old_data, $new_data, $changed_fields);
                                $success = t('operation_completed');
                            } else $error = "Error updating record: " . $connection->error;
                        }
                    }
                    break;
                case 'delete':
                    if (!has_permission('delete')) { $error = "You don't have permission to delete records"; break; }
                    if (isset($_POST['id'])) {
                        $delete_id = $connection->real_escape_string($_POST['id']);
                        $old_sql = "SELECT * FROM {$db_config['table']} WHERE id = '$delete_id'";
                        $old_result = $connection->query($old_sql);
                        $old_data = $old_result->fetch_assoc();
                        $sql = "DELETE FROM {$db_config['table']} WHERE id = '$delete_id'";
                        if ($connection->query($sql)) {
                            log_change($connection, $db_config['table'], $delete_id, 'DELETE', $old_data, null, 'all_fields');
                            $success = t('item_deleted');
                        } else $error = "Error deleting record: " . $connection->error;
                    }
                    break;
            }
        } catch (Exception $e) { $error = $e->getMessage(); }
    }
}

// Load data for logged in users
if ($is_logged_in && !$error) {
    try {
        $data_connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
        if ($data_connection->connect_error) throw new Exception("Connection failed: " . $data_connection->connect_error);
        $global_connection = $data_connection;
        
        // Load MFA admin data if needed
        if ($show_mfa_admin && has_permission('manage_mfa')) {
            $users_result = $data_connection->query("SELECT id, username, full_name, role, is_active FROM {$db_config['users_table']} ORDER BY username");
            if ($users_result) {
                while ($user = $users_result->fetch_assoc()) {
                    $mfa_status = get_user_mfa_status($data_connection, $user['id']);
                    $user_mfa_statuses[] = [
                        'user' => $user,
                        'mfa_status' => $mfa_status
                    ];
                }
            }
        }
        
        $columns = getTableColumns($data_connection, $db_config['table']);
        $column_names = [];
        foreach ($columns as $col) $column_names[] = $col['Field'];
        $sql = "SELECT * FROM {$db_config['table']}";
        if (isset($_GET['sort'])) {
            $requested_sort_column = $_GET['sort'];
            if (validateColumnExists($data_connection, $db_config['table'], $requested_sort_column)) {
                $sort_column = $requested_sort_column;
                $sort_direction = isset($_GET['dir']) && $_GET['dir'] === 'desc' ? 'DESC' : 'ASC';
                $sql .= " ORDER BY `$sort_column` $sort_direction";
            } else $error = "Invalid sort column: '$requested_sort_column'. Available columns: " . implode(', ', $column_names);
        } else {
            $verwerkingsactiviteit_exists = validateColumnExists($data_connection, $db_config['table'], 'verwerkingsactiviteit');
            if ($verwerkingsactiviteit_exists) $sql .= " ORDER BY verwerkingsactiviteit ASC";
            else $sql .= " ORDER BY id ASC";
        }
        $count_sql = "SELECT COUNT(*) as total FROM {$db_config['table']}";
        $count_result = $data_connection->query($count_sql);
        if ($count_result) $total_rows = $count_result->fetch_assoc()['total'];
        try {
            $result = $data_connection->query($sql);
            if (!$result) throw new Exception("Query failed: " . $data_connection->error . " | SQL: " . $sql);
        } catch (Exception $e) { $error = $e->getMessage(); $result = null; }
        $all_records = [];
        if ($result) {
            $result->data_seek(0);
            while ($row = $result->fetch_assoc()) $all_records[] = $row;
            $result->data_seek(0);
        }
        $records_to_update = get_records_not_recently_updated($data_connection);
        $count_records_to_update = get_count_records_not_recently_updated($data_connection);
        $update_statistics = get_update_statistics($data_connection);
        if (isset($_GET['edit'])) {
            if (has_permission('edit')) {
                $edit_id = $data_connection->real_escape_string($_GET['edit']);
                $edit_result = $data_connection->query("SELECT * FROM {$db_config['table']} WHERE id = '$edit_id' LIMIT 1");
                if ($edit_result && $edit_result->num_rows > 0) {
                    $edit_row = $edit_result->fetch_assoc();
                    foreach ($rot47_columns as $col) {
                        if (isset($edit_row[$col]) && $edit_row[$col] !== null) $edit_row[$col] = rot47_decrypt($edit_row[$col]);
                    }
                }
            } else $error = "You don't have permission to edit records";
        }
        if ($print_compact && has_permission('print')) $compact_data = get_compact_table_data_updated($data_connection, $all_records, $rot47_columns);
        if ($print_individual > 0 && $print_full_details && has_permission('print')) $full_record_details = get_full_record_details_for_print($data_connection, $print_individual, $rot47_columns);
        if ($print_all_with_dpia && has_permission('print')) $batch_records = get_all_records_with_dpia_for_print($data_connection, $rot47_columns, $only_with_dpia);
        if ($edit_dpia_id > 0) $dpia_info = get_dpia_info($data_connection, $edit_dpia_id);
        elseif ($view_dpia_id > 0) $dpia_info = get_dpia_info($data_connection, $view_dpia_id);
        $record_name = ''; $security_measures = '';
        if ($add_dpia_record > 0) {
            $record_name = get_record_verwerkingsactiviteit($data_connection, $add_dpia_record);
            $security_measures = get_security_measures_from_record($data_connection, $add_dpia_record);
        }
        $users_list = [];
        if (has_permission('manage_users')) {
            $users_result = $data_connection->query("SELECT * FROM {$db_config['users_table']} ORDER BY username");
            if ($users_result) while ($user = $users_result->fetch_assoc()) $users_list[] = $user;
        }
        if ($show_changes || isset($_GET['view_changes'])) {
            if (has_permission('view_changes') || (has_permission('view_own_changes') && !has_permission('view_changes'))) {
                $changes_sql = "SELECT c.*, u.username, u.full_name 
                               FROM {$db_config['changes_table']} c 
                               LEFT JOIN {$db_config['users_table']} u ON c.changed_by = u.id";
                if (!has_permission('view_changes') && has_permission('view_own_changes')) $changes_sql .= " WHERE c.changed_by = {$current_user['id']}";
                $changes_sql .= " ORDER BY c.changed_at DESC LIMIT 100";
                $changes_result = $data_connection->query($changes_sql);
                if ($changes_result) {
                    while ($change = $changes_result->fetch_assoc()) {
                        if ($change['old_data']) $change['old_data'] = json_decode($change['old_data'], true);
                        if ($change['new_data']) $change['new_data'] = json_decode($change['new_data'], true);
                        $changes[] = $change;
                    }
                }
                $show_changes = true;
            }
        }
        if ($show_dpia_list) {
            $dpias = get_all_dpias($data_connection, $dpia_status_filter);
            $all_dpias_count = count(get_all_dpias($data_connection, null));
            $open_dpias_count = count(get_all_dpias($data_connection, 'open'));
            $closed_dpias_count = count(get_all_dpias($data_connection, 'closed'));
            $pending_dpias_count = count(get_all_dpias($data_connection, 'pending'));
        }
    } catch (Exception $e) { $error = $e->getMessage(); }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= t('site_name') ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Arial', sans-serif; background: #fff; color: #000; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .login-container, .mfa-container { max-width: 400px; margin: 100px auto; background: #fff; border: 1px solid #000; padding: 2rem; }
        .login-title { text-align: center; margin-bottom: 1.5rem; font-size: 1.5rem; color: #000; }
        .form-group { margin-bottom: 1rem; }
        .form-label { display: block; margin-bottom: 0.5rem; color: #000; }
        .form-input { width: 100%; padding: 0.75rem; border: 1px solid #000; background: #fff; color: #000; }
        header { background: #000; color: #fff; padding: 2rem; margin-bottom: 2rem; border: 1px solid #000; }
        header h1 { font-size: 2rem; margin-bottom: 0.5rem; font-weight: normal; }
        header p { opacity: 0.8; font-size: 1rem; }
        nav { background: #f8f8f8; padding: 1rem; border: 1px solid #000; margin-bottom: 2rem; }
        .nav-links { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .nav-links a, .nav-link-btn { color: #000; text-decoration: none; padding: 0.75rem 1.5rem; border: 1px solid #000; background: #fff; transition: all 0.2s; font-size: 0.9rem; cursor: pointer; font-family: inherit; }
        .nav-links a:hover, .nav-links a.active, .nav-link-btn:hover { background: #000; color: #fff; }
        .btn { display: inline-block; padding: 0.75rem 1.5rem; background: #000; color: #fff; text-decoration: none; border: 1px solid #000; cursor: pointer; transition: all 0.2s; font-size: 0.9rem; }
        .btn:hover { background: #fff; color: #000; }
        .btn-outline { background: #fff; color: #000; }
        .btn-outline:hover { background: #000; color: #fff; }
        .btn-sm { padding: 0.5rem 1rem; font-size: 0.8rem; }
        .alert { padding: 1rem; border: 1px solid #000; margin-bottom: 1rem; }
        .alert-success { background: #f8f8f8; }
        .alert-danger { background: #fff; border-color: #d00; }
        .alert-warning { background: #fff3cd; border-color: #ffc107; }
        .table-responsive { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; background: #fff; }
        th, td { padding: 1rem; text-align: left; border-bottom: 1px solid #000; }
        th { background: #f8f8f8; font-weight: bold; }
        tr:hover { background: #f8f8f8; }
        .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 3px; font-size: 0.8rem; font-weight: bold; }
        .badge-success { background: #4CAF50; color: white; }
        .badge-warning { background: #ff9800; color: white; }
        .badge-danger { background: #f44336; color: white; }
        .badge-info { background: #2196F3; color: white; }
        .badge-secondary { background: #9e9e9e; color: white; }
        .mfa-secret-box { background: #f8f8f8; border: 1px solid #000; padding: 1rem; margin: 1rem 0; font-family: 'Courier New', monospace; font-size: 1.2rem; text-align: center; word-break: break-all; }
        .backup-codes { background: #fff8e1; border: 1px solid #ffc107; padding: 1rem; margin: 1rem 0; font-family: 'Courier New', monospace; }
        .backup-code { padding: 0.5rem; margin: 0.25rem; background: white; border: 1px solid #ddd; display: inline-block; }
        .mfa-status-badge { padding: 0.25rem 0.75rem; border-radius: 3px; font-size: 0.8rem; font-weight: bold; margin-left: 0.5rem; }
        .mfa-enabled { background: #4CAF50; color: white; }
        .mfa-disabled { background: #f44336; color: white; }
        .tab-container { display: flex; border-bottom: 1px solid #000; margin-bottom: 1rem; }
        .tab { padding: 0.75rem 1.5rem; cursor: pointer; border: 1px solid #000; border-bottom: none; margin-right: 0.5rem; background: #f8f8f8; }
        .tab.active { background: #000; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .user-info { display: flex; align-items: center; gap: 1rem; margin-top: 1rem; }
        .user-role { padding: 0.25rem 0.75rem; border: 1px solid #000; font-size: 0.8rem; font-weight: bold; }
        .role-admin { background: #900; color: #fff; }
        .role-editor { background: #090; color: #fff; }
        .role-viewer { background: #009; color: #fff; }
        .messages { margin-bottom: 1rem; }
        @media print {
            * { background: transparent !important; color: #000 !important; box-shadow: none !important; text-shadow: none !important; }
            body { font-size: 9pt; line-height: 1.3; margin: 0; padding: 0.5cm; }
            .btn, .nav-links, .messages, .user-info, .mfa-status-badge, .tab-container { display: none !important; }
        }
    </style>
</head>
<body <?php if (($print_compact || ($print_individual > 0 && $print_full_details) || $print_all_with_dpia) && isset($_GET['auto_print'])): ?>onload="window.print();"<?php endif; ?>>
<div class="container">
    <?php if (!$is_logged_in || $mfa_required): ?>
        <?php if ($mfa_required && !$show_mfa_setup): ?>
            <!-- MFA Verification Page -->
            <div class="mfa-container">
                <div class="login-title"><?= t('mfa_required') ?></div>
                <div class="messages">
                    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error); ?></div><?php endif; ?>
                    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success); ?></div><?php endif; ?>
                </div>
                <p style="text-align:center;margin-bottom:1.5rem;"><?= t('enter_mfa_code') ?></p>
                
                <div class="tab-container">
                    <div class="tab active" onclick="switchTab('totp')">TOTP Code</div>
                    <div class="tab" onclick="switchTab('backup')">Backup Code</div>
                </div>
                
                <div id="totp-tab" class="tab-content active">
                    <form method="POST">
                        <input type="hidden" name="action" value="verify_mfa">
                        <div class="form-group">
                            <label class="form-label"><?= t('mfa_code') ?> (6 digits):</label>
                            <input type="text" name="mfa_code" class="form-input" pattern="[0-9]{6}" maxlength="6" required autocomplete="off" autofocus>
                        </div>
                        <div class="form-group">
                            <button type="submit" class="btn"><?= t('verify') ?></button>
                        </div>
                    </form>
                </div>
                
                <div id="backup-tab" class="tab-content">
                    <form method="POST">
                        <input type="hidden" name="action" value="verify_mfa">
                        <div class="form-group">
                            <label class="form-label"><?= t('mfa_backup_code') ?> (10 characters):</label>
                            <input type="text" name="backup_code" class="form-input" pattern="[A-Z0-9]{10}" maxlength="10" required autocomplete="off">
                        </div>
                        <div class="form-group">
                            <button type="submit" class="btn"><?= t('use_backup_code') ?></button>
                        </div>
                    </form>
                </div>
                
                <div style="text-align:center;margin-top:1rem;">
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" class="btn btn-outline"><?= t('cancel') ?></button>
                    </form>
                </div>
            </div>
            
            <script>
                function switchTab(tabName) {
                    document.querySelectorAll('.tab-content').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    document.querySelectorAll('.tab').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    
                    document.getElementById(tabName + '-tab').classList.add('active');
                    event.target.classList.add('active');
                }
                
                // Auto-submit when 6 digits entered
                document.querySelector('input[name="mfa_code"]')?.addEventListener('input', function() {
                    if (this.value.length === 6) {
                        this.form.submit();
                    }
                });
            </script>
            
        <?php elseif ($show_mfa_setup): ?>
            <!-- MFA Setup Page -->
            <div class="mfa-container">
                <div class="login-title"><?= t('mfa_setup') ?></div>
                <div class="messages">
                    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error); ?></div><?php endif; ?>
                    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success); ?></div><?php endif; ?>
                </div>
                
                <?php
                // Generate the secret key
                $secret_key = generate_secret_key();
                ?>
                
                <p style="margin-bottom:1rem;"><?= t('mfa_secret_key') ?>:</p>
                <div class="mfa-secret-box" id="secret-key">
                    <?= chunk_split($secret_key, 4, ' '); ?>
                </div>
                <div style="text-align:center;margin-bottom:1rem;">
                    <button onclick="copySecretKey()" class="btn btn-sm"><?= t('copy_secret_key') ?></button>
                </div>
                
                <p style="margin-bottom:1rem;"><?= t('backup_codes') ?>:</p>
                <div class="backup-codes">
                    <?php 
                    $backup_codes = generate_backup_codes();
                    foreach ($backup_codes as $code): ?>
                        <span class="backup-code"><?= $code ?></span>
                    <?php endforeach; ?>
                </div>
                <p style="font-size:0.9rem;color:#666;margin-bottom:1.5rem;"><?= t('save_backup_codes') ?></p>
                
                <form method="POST">
                    <input type="hidden" name="action" value="setup_mfa">
                    <input type="hidden" name="secret_key" value="<?= $secret_key ?>">
                    <div class="form-group">
                        <label class="form-label"><?= t('mfa_code') ?> (6 digits):</label>
                        <input type="text" name="mfa_code" class="form-input" pattern="[0-9]{6}" maxlength="6" required autocomplete="off" placeholder="Enter code from authenticator app" autofocus>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn"><?= t('enable_mfa') ?></button>
                        <a href="?" class="btn btn-outline"><?= t('cancel') ?></a>
                    </div>
                </form>
            </div>
            
            <script>
                function copySecretKey() {
                    const secretKey = document.getElementById('secret-key').textContent.replace(/\s/g, '');
                    navigator.clipboard.writeText(secretKey).then(() => {
                        alert('Secret key copied to clipboard');
                    });
                }
                
                // Auto-submit when 6 digits entered
                document.querySelector('input[name="mfa_code"]')?.addEventListener('input', function() {
                    if (this.value.length === 6) {
                        this.form.submit();
                    }
                });
            </script>
            
        <?php else: ?>
            <!-- Login Page -->
            <div class="login-container">
                <div class="login-title"><?= t('site_name') ?> - <?= t('login') ?></div>
                <div class="messages">
                    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error); ?></div><?php endif; ?>
                    <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success); ?></div><?php endif; ?>
                </div>
                <form method="POST" class="login-form">
                    <input type="hidden" name="action" value="login">
                    <div class="form-group">
                        <label class="form-label"><?= t('username') ?>:</label>
                        <input type="text" name="username" class="form-input" required autofocus>
                    </div>
                    <div class="form-group">
                        <label class="form-label"><?= t('password') ?>:</label>
                        <input type="password" name="password" class="form-input" required>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn"><?= t('login') ?></button>
                    </div>
                </form>
                <div style="text-align:center;margin-top:15px;font-size:0.9rem;color:#666;">Default admin: admin / admin123</div>
            </div>
        <?php endif; ?>
        
    <?php else: ?>
        <!-- Main Application -->
        <?php if (!$print_individual && !$print_compact && !$print_all_with_dpia && !$show_mfa_admin): ?>
            <header>
                <h1><?= t('site_name') ?></h1>
                <p><?= t('welcome') ?></p>
                <div class="user-info">
                    <div>
                        <strong><?= htmlspecialchars($current_user['full_name']); ?></strong>
                        <div style="font-size:0.9rem;"><?= htmlspecialchars($current_user['username']); ?></div>
                    </div>
                    <div class="user-role role-<?= htmlspecialchars($current_user['role']); ?>">
                        <?= strtoupper(htmlspecialchars($current_user['role'])); ?>
                    </div>
                    <?php if ($is_logged_in && $current_user && !isset($_GET['setup_mfa'])): 
                        // Check MFA status
                        $mfa_enabled = false;
                        try {
                            $connection = new mysqli($db_config['host'], $db_config['username'], $db_config['password'], $db_config['database']);
                            if (!$connection->connect_error) {
                                $mfa_status = get_user_mfa_status($connection, $current_user['id']);
                                $mfa_enabled = $mfa_status['enabled'];
                                $connection->close();
                            }
                        } catch (Exception $e) {
                            // Silently fail
                        }
                        
                        if (!$mfa_enabled): ?>
                            <a href="?setup_mfa=1" class="nav-link-btn" style="background:#ff9800;color:white;">🔒 Setup MFA Now</a>
                        <?php endif; ?>
                    <?php endif; ?>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" class="btn btn-sm"><?= t('logout') ?></button>
                    </form>
                </div>
            </header>
            
            <nav>
                <div class="nav-links">
                    <a href="?" class="home-btn">🏠 <?= t('home') ?></a>
                    <?php if (has_permission('view_changes') || has_permission('view_own_changes')): ?>
                        <form method="POST" style="display:inline;">
                            <input type="hidden" name="action" value="show_changes">
                            <button type="submit" class="nav-link-btn"><?= t('review_mode') ?></button>
                        </form>
                    <?php endif; ?>
                    <?php if (has_permission('manage_dpia')): ?>
                        <form method="POST" style="display:inline;">
                            <input type="hidden" name="action" value="show_dpias">
                            <button type="submit" class="nav-link-btn"><?= t('dpia_management') ?></button>
                        </form>
                    <?php endif; ?>
                    <?php if (has_permission('manage_mfa')): ?>
                        <a href="?mfa_admin=1" class="nav-link-btn">🔐 <?= t('mfa_admin_management') ?></a>
                    <?php endif; ?>
                    <?php if (has_permission('print')): ?>
                        <a href="?print_compact=1&auto_print=1" class="nav-link-btn" title="<?= t('print_compact_table') ?>">🖨️ <?= t('print_compact') ?></a>
                        <a href="?print_all_with_dpia=1&auto_print=1" class="nav-link-btn" title="<?= t('print_all_with_dpia_description') ?>">📚 <?= t('print_all_with_dpia') ?></a>
                    <?php endif; ?>
                </div>
            </nav>
            
            <div class="messages">
                <?php if ($error): ?><div class="alert alert-danger"><?= t('error') ?>: <?= htmlspecialchars($error); ?></div><?php endif; ?>
                <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success); ?></div><?php endif; ?>
            </div>
            
        <?php endif; ?>
        
        <!-- MFA Admin Management -->
        <?php if ($show_mfa_admin && has_permission('manage_mfa')): ?>
            <div class="card" style="background:#fff;padding:1.5rem;border:1px solid #000;margin-bottom:1.5rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem;">
                    <h2 style="font-size:1.5rem;font-weight:normal;margin:0;"><?= t('mfa_admin_management') ?></h2>
                    <a href="?" class="btn"><?= t('back') ?></a>
                </div>
                
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th><?= t('username') ?></th>
                                <th><?= t('full_name') ?></th>
                                <th><?= t('role') ?></th>
                                <th><?= t('mfa_status') ?></th>
                                <th><?= t('last_updated') ?></th>
                                <th><?= t('actions') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($user_mfa_statuses as $item): 
                                $user = $item['user'];
                                $mfa_status = $item['mfa_status'];
                            ?>
                                <tr>
                                    <td><?= htmlspecialchars($user['id']); ?></td>
                                    <td><?= htmlspecialchars($user['username']); ?></td>
                                    <td><?= htmlspecialchars($user['full_name']); ?></td>
                                    <td><?= htmlspecialchars($user['role']); ?></td>
                                    <td>
                                        <?php if ($mfa_status['enabled']): ?>
                                            <span class="mfa-status-badge mfa-enabled">✓ <?= t('mfa_enabled') ?></span>
                                        <?php else: ?>
                                            <span class="mfa-status-badge mfa-disabled">✗ <?= t('mfa_disabled') ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= htmlspecialchars($mfa_status['last_updated'] ?? 'N/A'); ?></td>
                                    <td style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                                        <?php if ($mfa_status['enabled']): ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="mfa_admin_action" value="force_disable">
                                                <input type="hidden" name="user_id" value="<?= $user['id']; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline" onclick="return confirm('Force disable MFA for this user?')">
                                                    <?= t('force_mfa_disable') ?>
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="mfa_admin_action" value="force_enable">
                                                <input type="hidden" name="user_id" value="<?= $user['id']; ?>">
                                                <button type="submit" class="btn btn-sm" onclick="return confirm('Force enable MFA for this user?')">
                                                    <?= t('force_mfa_enable') ?>
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
        <?php else: ?>
            <!-- Rest of the application -->
            <?php if (has_permission('view') && !isset($_GET['add']) && !$edit_row && !$show_changes && !$show_user_form && !$show_dpia_list && !$add_dpia_record && !$edit_dpia_id && !$view_dpia_id): ?>
                <?php if ($result && $result->num_rows > 0): ?>
                    <div style="background:#f8f8f8;padding:1rem;border:1px solid #000;margin-bottom:1rem;text-align:center;font-weight:bold;">
                        <?php $current = $result ? $result->num_rows : 0; echo str_replace(['{current}', '{total}'], [$current, $total_rows], t('row_counter')); ?>
                        <?php if ($count_records_to_update > 0): ?>
                            <div style="margin-top:0.5rem;color:#ff9800;font-weight:bold;">⚠️ <?= t('update_required') ?>: <?= $count_records_to_update ?> <?= t('records_need_update') ?></div>
                        <?php endif; ?>
                    </div>
                    
                    <div style="background:#fff;padding:1.5rem;border:1px solid #000;margin-bottom:1.5rem;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem;">
                            <h2 style="font-size:1.5rem;font-weight:normal;margin:0;"><?= t('processing_activities') ?> (<?= $result->num_rows ?>)</h2>
                            <div style="display:flex;gap:0.5rem;">
                                <?php if (has_permission('add')): ?>
                                    <a href="?add=1" class="btn btn-outline"><?= t('add_record_form') ?>
                                        <?php if ($count_records_to_update > 0): ?>
                                            <span style="background:#ff9800;color:white;padding:0.25rem 0.5rem;border-radius:3px;font-size:0.8rem;font-weight:bold;margin-left:0.5rem;"><?= $count_records_to_update ?></span>
                                        <?php endif; ?>
                                    </a>
                                <?php endif; ?>
                                <?php if (!empty($records_to_update)): ?>
                                    <button class="btn btn-outline" onclick="showUpdateRecommendations()">⚠️ <?= t('update_recommendations') ?> (<?= $count_records_to_update ?>)</button>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <div class="table-responsive">
                            <table>
                                <thead>
                                    <tr>
                                        <?php $visible_columns = array_slice($columns, 0, 4); foreach ($visible_columns as $col): 
                                            $col_name = $col['Field']; 
                                            $is_valid_column = true;
                                            $sort_url = "?"; 
                                            if ($is_valid_column) { 
                                                $sort_url = "?sort=" . urlencode($col_name) . "&dir="; 
                                                $sort_url .= ($sort_column === $col_name && $sort_direction === 'ASC') ? 'desc' : 'asc'; 
                                            } 
                                            $is_encrypted = in_array($col_name, $rot47_columns); 
                                            $is_timestamp = ($col_name === 'created_at' || $col_name === 'updated_at'); 
                                        ?>
                                            <th>
                                                <?php if ($is_valid_column): ?>
                                                    <a href="<?= $sort_url; ?>" style="color:#000;text-decoration:none;">
                                                        <?= htmlspecialchars($col_name); ?>
                                                        <?php if ($is_timestamp): ?><span style="color:#006;font-weight:bold;">[auto]</span><?php endif; ?>
                                                        <?php if ($is_encrypted): ?><span style="color:#900;font-weight:bold;font-size:0.8rem;"><?= t('encrypted_indicator') ?></span><?php endif; ?>
                                                        <?php if ($sort_column === $col_name): ?><?= $sort_direction === 'ASC' ? '↑' : '↓'; ?><?php endif; ?>
                                                    </a>
                                                <?php else: ?>
                                                    <?= htmlspecialchars($col_name); ?>
                                                    <?php if ($is_timestamp): ?><span style="color:#006;font-weight:bold;">[auto]</span><?php endif; ?>
                                                    <?php if ($is_encrypted): ?><span style="color:#900;font-weight:bold;font-size:0.8rem;"><?= t('encrypted_indicator') ?></span><?php endif; ?>
                                                <?php endif; ?>
                                            </th>
                                        <?php endforeach; ?>
                                        <th><?= t('dpia_status') ?></th>
                                        <th><?= t('actions') ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php $row_counter = 0; $result->data_seek(0); while ($row = $result->fetch_assoc()): $row_counter++;
                                        if (isset($global_connection) && $global_connection) { 
                                            $has_dpia_record = has_dpia($global_connection, $row['id']); 
                                            $dpia_record_info = $has_dpia_record ? get_dpia_info_by_record($global_connection, $row['id']) : null; 
                                        } else { 
                                            $has_dpia_record = false; 
                                            $dpia_record_info = null; 
                                        }
                                        $needs_update = false; 
                                        $days_since_update = 0; 
                                        $priority = 'none'; 
                                        $priority_color = '#4CAF50'; 
                                        if (!empty($row['updated_at'])) { 
                                            $days_since_update = floor((time() - strtotime($row['updated_at'])) / (60 * 60 * 24)); 
                                            $needs_update = $days_since_update > $recent_update_threshold; 
                                            $priority = get_update_priority($days_since_update); 
                                            $priority_color = get_priority_color($priority); 
                                        } 
                                    ?>
                                        <tr <?php if ($needs_update): ?>style="border-left:4px solid <?= $priority_color ?>;"<?php endif; ?>>
                                            <?php $visible_columns = array_slice($columns, 0, 4); foreach ($visible_columns as $col): 
                                                $col_name = $col['Field']; 
                                                $value = isset($row[$col_name]) ? $row[$col_name] : '';
                                                $is_encrypted = in_array($col_name, $rot47_columns); 
                                                if ($is_encrypted && $value !== null && $value !== '') $value = rot47_decrypt($value); 
                                                $is_timestamp = ($col_name === 'created_at' || $col_name === 'updated_at'); 
                                                $is_created_at = ($col_name === 'created_at'); 
                                                $is_updated_at = ($col_name === 'updated_at'); 
                                            ?>
                                                <td title="<?= htmlspecialchars($value); ?>" <?php if ($is_timestamp): ?>style="background-color:#f9f9f9;font-family:'Courier New',monospace;color:#006;"<?php endif; ?>>
                                                    <?php if (strlen($value) > 50 && !$is_timestamp) echo htmlspecialchars(substr($value, 0, 47)) . '...'; else echo htmlspecialchars($value); ?>
                                                    <?php if ($is_encrypted && $value !== ''): ?><span style="color:#900;font-weight:bold;font-size:0.7rem;">✓</span><?php endif; ?>
                                                    <?php if ($is_created_at): ?>
                                                        <div style="font-size:0.7rem;color:#666;margin-top:0.25rem;"><?= t('created') ?></div>
                                                    <?php elseif ($is_updated_at): ?>
                                                        <div style="font-size:0.7rem;color:#666;margin-top:0.25rem;"><?= t('updated') ?>
                                                            <?php if ($needs_update): ?>
                                                                <span style="color:<?= $priority_color ?>;font-weight:bold;">(<?= $days_since_update ?> <?= t('days_ago') ?>)</span>
                                                            <?php endif; ?>
                                                        </div>
                                                    <?php endif; ?>
                                                </td>
                                            <?php endforeach; ?>
                                            <td>
                                                <?php if ($has_dpia_record && $dpia_record_info): ?>
                                                    <span style="display:inline-block;padding:0.25rem 0.5rem;border-radius:3px;font-size:0.8rem;font-weight:bold;margin-left:0.5rem;background:#ff9800;color:white;"><?= htmlspecialchars(ucfirst($dpia_record_info['status'])); ?></span><br>
                                                    <small>
                                                        <a href="?view_dpia=<?= htmlspecialchars($dpia_record_info['id']); ?>"><?= t('view_dpia') ?></a>
                                                        <?php if (has_permission('manage_dpia')): ?> | <a href="?edit_dpia=<?= htmlspecialchars($dpia_record_info['id']); ?>"><?= t('edit_dpia') ?></a><?php endif; ?>
                                                    </small>
                                                <?php else: ?>
                                                    <span class="badge badge-secondary"><?= t('no_dpia') ?></span>
                                                    <?php if (has_permission('manage_dpia')): ?>
                                                        <br><small><a href="?add_dpia=<?= htmlspecialchars($row['id']); ?>"><?= t('register_dpia') ?></a></small>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </td>
                                            <td style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                                                <?php if ($needs_update): ?>
                                                    <span class="badge badge-warning" title="<?= t('not_updated_recently') ?>: <?= $days_since_update ?> <?= t('days_ago') ?>" style="background-color:<?= $priority_color ?>;">
                                                        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:0.25rem;background-color:white;"></span>
                                                        <?php if ($priority == 'high'): ?>⚠️ <?= t('high_priority') ?>
                                                        <?php elseif ($priority == 'medium'): ?>⚠️ <?= t('medium_priority') ?>
                                                        <?php else: ?>⚠️ <?= t('low_priority') ?><?php endif; ?>
                                                    </span>
                                                <?php endif; ?>
                                                <?php if (has_permission('print')): ?>
                                                    <a href="?print_record=<?= htmlspecialchars($row['id']); ?>&print_full=1" class="btn btn-sm" title="<?= t('print_safe_version') ?>" style="background:#28a745;color:white;border:1px solid #28a745;">📄 <?= t('secure_print') ?></a>
                                                <?php endif; ?>
                                                <?php if (has_permission('edit')): ?>
                                                    <a href="?edit=<?= htmlspecialchars($row['id']); ?>" class="btn btn-sm btn-outline"><?= t('edit_record') ?></a>
                                                <?php endif; ?>
                                                <?php if (has_permission('delete')): ?>
                                                    <form method="POST" style="display:inline;">
                                                        <input type="hidden" name="action" value="delete">
                                                        <input type="hidden" name="id" value="<?= htmlspecialchars($row['id']); ?>">
                                                        <button type="submit" class="btn btn-sm btn-outline" onclick="return confirm('<?= t('confirm_delete') ?>')"><?= t('delete') ?></button>
                                                    </form>
                                                <?php endif; ?>
                                                <?php if ($has_dpia_record && has_permission('manage_dpia')): ?>
                                                    <form method="POST" style="display:inline;">
                                                        <input type="hidden" name="dpia_action" value="remove_dpia">
                                                        <input type="hidden" name="record_id" value="<?= htmlspecialchars($row['id']); ?>">
                                                        <button type="submit" class="btn btn-sm btn-outline" onclick="return confirm('<?= t('confirm_remove_dpia') ?>')"><?= t('remove_dpia') ?></button>
                                                    </form>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endwhile; ?>
                                </tbody>
                            </table>
                        </div>
                        <div style="padding:1rem;border-top:1px solid #000;background:#f8f8f8;display:flex;justify-content:space-between;font-size:0.9rem;">
                            <div><?= t('showing_columns') ?>: 4 <?= t('of') ?> <?= count($columns); ?> | <?= t('encrypted_columns') ?>: <?= count($rot47_columns); ?></div>
                            <div>
                                <?php if ($count_records_to_update > 0): ?>
                                    <span style="color:#ff9800;font-weight:bold;margin-right:1rem;">⚠️ <?= $count_records_to_update ?> <?= t('records_need_update') ?></span>
                                <?php endif; ?>
                                <?= t('user') ?>: <?= htmlspecialchars($current_user['username']); ?> (<?= htmlspecialchars($current_user['role']); ?>)
                            </div>
                        </div>
                    </div>
                <?php elseif ($result && $result->num_rows === 0): ?>
                    <div class="alert alert-danger" style="text-align:center;"><?= t('no_activities_found') ?></div>
                <?php elseif ($error): ?>
                    <div class="alert alert-danger" style="text-align:center;"><?= t('database_error') ?>: <?= htmlspecialchars($error); ?></div>
                <?php endif; ?>
            <?php endif; ?>
        <?php endif; ?>
    <?php endif; ?>
</div>

<script>
    // Auto-hide success messages
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert-success');
        alerts.forEach(alert => alert.style.display = 'none');
    }, 5000);
    
    // Scroll to form if editing/adding
    document.addEventListener('DOMContentLoaded', function() {
        const params = new URLSearchParams(window.location.search);
        if (params.has('edit') || params.has('add')) {
            const form = document.getElementById('add-form');
            if (form) form.scrollIntoView({ behavior: 'smooth' });
        }
    });
    
    // Update recommendations modal
    function showUpdateRecommendations() {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.cssText = `position:fixed;top:0;left:0;width:100%;height:100%;background-color:rgba(0,0,0,0.8);display:flex;justify-content:center;align-items:center;z-index:1000;overflow:auto;padding:1rem;`;
        
        const card = document.createElement('div');
        card.className = 'card';
        card.style.cssText = `max-width:800px;width:95%;max-height:90vh;overflow-y:auto;background:white;`;
        
        let content = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem;padding:1.5rem;border-bottom:1px solid #000;">
            <h2 style="font-size:1.5rem;font-weight:normal;margin:0;">${t('update_recommendations')}</h2>
            <button onclick="closeModal()" class="btn">× Close</button>
        </div>
        <div style="padding:1.5rem;">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:1.5rem;">
                <div style="background:#f8f8f8;padding:1rem;border:1px solid #ddd;border-radius:3px;text-align:center;">
                    <div style="font-size:1.5rem;font-weight:bold;margin-bottom:0.25rem;">${<?= $update_statistics['total_records'] ?? 0 ?>}</div>
                    <div style="color:#666;font-size:0.8rem;">${t('total_records')}</div>
                </div>
                <div style="background:#f8f8f8;padding:1rem;border:1px solid #ff9800;border-radius:3px;text-align:center;">
                    <div style="font-size:1.5rem;font-weight:bold;margin-bottom:0.25rem;color:#ff9800;">${<?= $update_statistics['needs_update'] ?? 0 ?>}</div>
                    <div style="color:#666;font-size:0.8rem;">${t('needs_update')}</div>
                </div>
                <div style="background:#f8f8f8;padding:1rem;border:1px solid #4CAF50;border-radius:3px;text-align:center;">
                    <div style="font-size:1.5rem;font-weight:bold;margin-bottom:0.25rem;color:#4CAF50;">${<?= $update_statistics['up_to_date'] ?? 0 ?>}</div>
                    <div style="color:#666;font-size:0.8rem;">${t('up_to_date')}</div>
                </div>
                <div style="background:#f8f8f8;padding:1rem;border:1px solid #ddd;border-radius:3px;text-align:center;">
                    <div style="font-size:1.5rem;font-weight:bold;margin-bottom:0.25rem;">${<?= $update_statistics['average_days_since_update'] ?? 0 ?>}</div>
                    <div style="color:#666;font-size:0.8rem;">${t('average_update_age')}</div>
                </div>
            </div>
            <h3 style="margin-bottom:1rem;">${t('records_to_update')}</h3>
            <div style="max-height:400px;overflow-y:auto;">`;
        
        <?php foreach ($records_to_update as $record): ?>
            <?php $days_since = $record['days_since_update']; $priority = get_update_priority($days_since); $priority_color = get_priority_color($priority); $warning_class = $days_since > 365 ? 'danger' : 'warning'; ?>
            content += `<div style="padding:0.75rem;border:1px solid #eee;margin-bottom:0.5rem;border-radius:3px;border-left-color:<?= $priority_color ?>;">
                <div style="font-weight:bold;color:#000;margin-bottom:0.25rem;"><?= htmlspecialchars($record['verwerkingsactiviteit'] ?? 'Record #' . $record['id']); ?></div>
                <div style="display:flex;justify-content:space-between;font-size:0.8rem;color:#666;">
                    <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:0.5rem;background-color:<?= $priority_color ?>"></span>${t('last_update')}: <?= $days_since ?> ${t('days_ago')}</span>
                    <a href="?edit=<?= $record['id'] ?>" class="btn btn-sm">${t('edit')}</a>
                </div>
            </div>`;
        <?php endforeach; ?>
        
        content += `</div></div>`;
        
        card.innerHTML = content;
        modal.appendChild(card);
        document.body.appendChild(modal);
        document.body.style.overflow = 'hidden';
        
        modal.addEventListener('click', function(event) {
            if (event.target === modal) closeModal();
        });
        
        window.closeModal = function() {
            modal.remove();
            document.body.style.overflow = '';
        };
    }
</script>
</body>
</html>
