-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generated on: 10 jul 2026 om 13:12
-- Server version: 10.11.6-MariaDB
-- PHP version: 8.2.28

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `prd-avg-register-voedselbankalmere`
--

-- --------------------------------------------------------

--
-- Table structure for table `data_breaches`
--

CREATE TABLE `data_breaches` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `breach_date` date NOT NULL,
  `discovery_date` date NOT NULL,
  `breach_type` enum('confidentiality','integrity','availability','mixed') NOT NULL,
  `personal_data_affected` text NOT NULL,
  `affected_data_subjects` int(11) DEFAULT NULL,
  `causes` text NOT NULL,
  `measures_taken` text NOT NULL,
  `notified_authority` enum('yes','no','in_progress') DEFAULT 'no',
  `notification_date` date DEFAULT NULL,
  `notified_affected_persons` enum('yes','no','in_progress') DEFAULT 'no',
  `risk_level` enum('low','medium','high') NOT NULL,
  `status` enum('open','investigating','contained','resolved','closed') DEFAULT 'open',
  `reported_by` int(11) NOT NULL,
  `assigned_to` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Data export for table `data_breaches`
--

INSERT INTO `data_breaches` (`id`, `title`, `description`, `breach_date`, `discovery_date`, `breach_type`, `personal_data_affected`, `affected_data_subjects`, `causes`, `measures_taken`, `notified_authority`, `notification_date`, `notified_affected_persons`, `risk_level`, `status`, `reported_by`, `assigned_to`, `created_at`, `updated_at`) VALUES
(4, 'test', 'test', '2026-05-20', '2026-05-20', 'confidentiality', 'test', NULL, 'test', 'test', 'no', NULL, 'no', 'low', 'open', 100000006, NULL, '2026-05-20 09:50:02', '2026-05-20 09:50:02');

-- --------------------------------------------------------

--
-- Table structure for table `dpia_registrations`
--

CREATE TABLE `dpia_registrations` (
  `id` int(11) NOT NULL,
  `record_id` int(11) NOT NULL,
  `description` text DEFAULT NULL,
  `necessity_proportionality` text DEFAULT NULL,
  `mitigation_measures` text DEFAULT NULL,
  `residual_risk` text DEFAULT NULL,
  `overall_risk_level` enum('low','medium','high') DEFAULT 'medium',
  `status` enum('draft','in_progress','under_review','approved','rejected','implemented') NOT NULL DEFAULT 'draft',
  `registered_by` int(11) NOT NULL,
  `registered_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `notes` text DEFAULT NULL,
  `title` varchar(255) NOT NULL DEFAULT 'DPIA Assessment',
  `review_date` date DEFAULT NULL,
  `processing_activity_description` text DEFAULT NULL,
  `risk_origin` enum('new_technology','large_scale','sensitive_data','systematic_monitoring','combination_datasets','vulnerable_groups','other') DEFAULT 'other',
  `necessity_test` text DEFAULT NULL,
  `proportionality_test` text DEFAULT NULL,
  `data_subjects_affected` int(11) DEFAULT 0,
  `data_categories` text DEFAULT NULL,
  `compliance_checklist` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`compliance_checklist`)),
  `risk_assessment_matrix` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`risk_assessment_matrix`)),
  `consultation_conducted` enum('yes','no','planned') DEFAULT 'no',
  `consultation_details` text DEFAULT NULL,
  `recommendations` text DEFAULT NULL,
  `management_approval` enum('pending','approved','rejected','revised') DEFAULT 'pending',
  `approved_by` int(11) DEFAULT NULL,
  `approval_date` date DEFAULT NULL,
  `necessity` text DEFAULT NULL,
  `proportionality` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Data export for table `dpia_registrations`
--

INSERT INTO `dpia_registrations` (`id`, `record_id`, `description`, `necessity_proportionality`, `mitigation_measures`, `residual_risk`, `overall_risk_level`, `status`, `registered_by`, `registered_at`, `updated_at`, `notes`, `title`, `review_date`, `processing_activity_description`, `risk_origin`, `necessity_test`, `proportionality_test`, `data_subjects_affected`, `data_categories`, `compliance_checklist`, `risk_assessment_matrix`, `consultation_conducted`, `consultation_details`, `recommendations`, `management_approval`, `approved_by`, `approval_date`, `necessity`, `proportionality`) VALUES
(300000003, 200000033, 'DPIA for payment processing at checkouts', NULL, 'Logging all transactions, regular audits, insight into transaction process', 'None.', 'medium', 'in_progress', 100000006, '2026-02-26 09:48:43', '2026-03-11 08:44:18', '', 'DPIA for payment processing at checkouts', '2026-02-26', 'Transaction processing of fictional supermarket item payments. Digital receipt with purchased items on own card.', 'other', 'Payment processing is necessary for the operation of fictional money cards. Processing is proportionate with strict security.', 'Minimal data storage. This still needs further elaboration by delving deeper into the process.', 1300, 'Grocery items, quantities, product price', NULL, NULL, 'no', '', '', 'pending', NULL, NULL, NULL, NULL),
(300000004, 200000028, 'Risk of processing the guidance of sick employees and reintegration of employees', NULL, 'Separate medical multi-file, strict access control with key on cabinet, minimal data collection. Black marker notes not required to be shown', 'High residual risk due to sensitive nature of medical data', 'medium', 'in_progress', 100000006, '2026-02-26 09:58:23', '2026-02-26 09:58:23', '', 'Guidance of sick employees and reintegration', '2026-02-26', 'Guidance of sick employees and reintegration', 'other', 'Processing is legally required for the reintegration obligation in case of long-term sick leave.', 'Only relevant medical data for reintegration is processed. Strict separation of medical and HR data.', 150, 'Medical data, sick leave history, reintegration plan, collective labor agreement protocols', NULL, NULL, 'no', '', '', 'pending', NULL, NULL, NULL, NULL),
(300000005, 200000014, 'Risk of processing bank transactions of donors', NULL, 'Shadow accounting process needs to be checked for pseudonymization', 'High risk of data breach in shadow administration', 'medium', 'in_progress', 100000006, '2026-02-26 10:05:47', '2026-02-26 10:05:47', '', 'Donor registration and donation administration', '2026-02-26', 'Donor registration and donation administration', 'other', 'Processing of bank transactions is essential for the continued existence of the Almere Food Bank.', 'No exports of bank transactions in csv or other format.', 1200, 'Names, bank account numbers and bank transaction amounts in euros', NULL, NULL, 'no', '', '', 'pending', NULL, NULL, NULL, NULL),
(300000006, 200000012, 'Risk of data breach with external service providers regarding the processing of food bank visitors and interested parties, such as employees for digital newsletter distribution', NULL, 'No exports of email addresses', '.', 'medium', 'in_progress', 100000006, '2026-02-26 10:17:56', '2026-05-05 09:06:05', '', 'Newsletter and communication with interested parties', '2026-02-26', 'Newsletter and communication with interested parties', 'other', '.', '.', 2500, '.', NULL, NULL, 'no', '', '', 'pending', NULL, NULL, NULL, NULL),
(300000007, 200000011, 'The processing of approximately 362 households/clients (excluding children) data carries risks regarding GDPR legislation. The legislation requires pseudonymization of all data containing personal data. This applies to', NULL, 'Multi-factor login on Microsoft Access\r\nMore security for role-based separation possibilities in Microsoft Access.\r\nHidden paths\r\nvba code and bat file with smoke screen where data is accessible\r\nOpportunities to participate with other software on the market, consider food banks that do things differently than us. What can we learn from that and adopt.\r\nNo exports of data outside the Microsoft engine', 'No possibility for pseudonymization yet.\r\nThe Microsoft Access engine has not yet offered an upgrade for this. We are waiting for this to limit the risks of copying data or a database hack.', 'medium', 'in_progress', 100000006, '2026-03-04 09:32:24', '2026-05-26 09:17:30', '', 'Risk of client activity registration for food aid', '2026-03-04', 'The processing of information about clients within the Almere Food Bank', 'other', 'Data is necessary to conduct an intake of what type of clients the Almere Food Bank has and how to assess their situation regarding food aid and furniture and clothing, by both intake and assessment committee. For this, we work together with intake agencies at the front end of the organization, think of aid agencies that help people pay off debts or the Salvation Army and governments such as local municipalities.', '550 households of which approximately 1300 persons (2025)\r\n\r\nData retention is that clients participate for a maximum of about 2 years. After those two years, clients should actually be self-sufficient again. We remove clients as soon as they no longer use food aid, so to speak inactive clients. After that, we want data to always be pseudonymized via Microsoft Access. Therefore, we are waiting for a migration to a new version of Microsoft Access on-site (not cloud). We also hope that they work on an engine that standardly migrates all data to rotated data so that in case of a data leak, data is not human-readable without understanding the rotation (reverse engineering to human-readable). The alternative is that we mainly look at what is available on the market. Unfortunately, this is not applicable, because live data is not easily translatable to an available package we deal with daily. Also, the human aspects such as working with the tools are an obstacle. We know that it is possible to pseudonymize via VBA code, but that is only possible for certain instructions and not for the whole. Therefore, we are waiting for Microsoft for a complete pseudonymization engine tool. Actually, Microsoft Access with its forms, sql queries and data filtering is still the best option.', 1300, 'Multiple personal data about income, expenses, type of clients. Also think of debts or clients who are war refugees or a business that got into trouble due to debts.', NULL, '{"major":{"rare":"1"}}', 'no', '', '', 'pending', NULL, NULL, NULL, NULL),
(300000008, 200000027, 'Risk of processing medical data for the registration of accidents and near-accidents', NULL, '.', '.', 'medium', 'in_progress', 100000006, '2026-03-04 10:28:22', '2026-03-04 12:26:01', '.', 'Registration of occupational accidents according to CAO and Arbowet', '2026-03-04', 'Registration of occupational accidents according to CAO and Arbowet', 'other', '.', '.', 10, 'internal employees (volunteers)', NULL, '{"catastrophic":{"rare":"1"}}', 'planned', '.', '.', 'pending', NULL, NULL, NULL, NULL),
(300000010, 200000038, '@lliCash Card issuance and client administration of the balance on the cards', NULL, '@lliCash', '@lliCash', 'medium', 'draft', 100000006, '2026-06-02 08:31:00', '2026-06-02 08:36:18', '', '@lliCash', NULL, '@lliCash', 'sensitive_data', '@lliCash', '@lliCash', 0, '@lliCash', NULL, NULL, 'no', '', '', 'pending', NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `gdpr_register`
--

CREATE TABLE `gdpr_register` (
  `id` int(11) NOT NULL,
  `has_processing_agreement_with_third_party` enum('Yes','No') DEFAULT 'No',
  `we_are_processor` enum('Yes','No') DEFAULT 'No',
  `processing_activity` varchar(500) NOT NULL,
  `name_data_controller` varchar(255) DEFAULT NULL,
  `contact_data_controller` varchar(255) DEFAULT NULL,
  `name_joint_data_controller` varchar(255) DEFAULT NULL,
  `contact_joint_data_controller` varchar(255) DEFAULT NULL,
  `name_representative` varchar(255) DEFAULT NULL,
  `contact_representative` varchar(255) DEFAULT NULL,
  `name_dpo` varchar(255) DEFAULT NULL,
  `contact_dpo` varchar(255) DEFAULT NULL,
  `purpose_of_processing` text NOT NULL,
  `legal_basis` varchar(300) NOT NULL,
  `categories_personal_data` text NOT NULL,
  `categories_data_subjects` varchar(300) NOT NULL,
  `categories_recipients` varchar(300) NOT NULL,
  `retention_periods` varchar(200) NOT NULL,
  `risk_level` enum('low','medium','high') NOT NULL,
  `technical_measures` text NOT NULL,
  `organizational_measures` text NOT NULL,
  `dpia_required` enum('yes','no') NOT NULL,
  `is_international_data_transfers` enum('yes','no','unknown') DEFAULT 'unknown',
  `to_country` enum('none','EU_EEA_Switzerland','UK','Argentina','Canada','Israel','Japan','New_Zealand','Republic_of_Korea','Uruguay','USA','Australia','Brazil','India','Mexico','Singapore','South_Africa','Other_third_country','Multiple_countries') DEFAULT 'none',
  `safeguards` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `review_due_date` date DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  `updated_by` int(11) DEFAULT NULL,
  `department` enum('administration','distribution','volunteers','donations','marketing','other') DEFAULT 'other',
  `status` enum('active','inactive','archived','review_needed') DEFAULT 'active',
  `legitimate_interest_description` text DEFAULT NULL,
  `dpia_status` enum('open','in_progress','completed','not_required') DEFAULT 'not_required'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Data export for table `gdpr_register`
--

INSERT INTO `gdpr_register` (`id`, `has_processing_agreement_with_third_party`, `we_are_processor`, `processing_activity`, `name_data_controller`, `contact_data_controller`, `name_joint_data_controller`, `contact_joint_data_controller`, `name_representative`, `contact_representative`, `name_dpo`, `contact_dpo`, `purpose_of_processing`, `legal_basis`, `categories_personal_data`, `categories_data_subjects`, `categories_recipients`, `retention_periods`, `risk_level`, `technical_measures`, `organizational_measures`, `dpia_required`, `is_international_data_transfers`, `to_country`, `safeguards`, `created_at`, `updated_at`, `review_due_date`, `created_by`, `updated_by`, `department`, `status`, `legitimate_interest_description`, `dpia_status`) VALUES
(200000011, 'No', 'No', 'Client activity registration for food aid', 'eVcyU1Y1SVBCaERtUXppRlRacXJJZz09OjrkZ83LimlBNg99yq/N5TZX', 'SjREMit1YTRycVRNd3hPS0J1a0RTb3RKWXY0V2dLL29idUhudDFscHB3VT06Or9FRyHclwlJ+QuMTbouwj4=', 'T1RLd3lsNnJKa3RvMExoZ0g2Z1pyWStUcUJ6aEc5T2VXV205ZUVQRlBtYz06Onzgsi2bQtrfmhQ+L+4PtRk=', 'ZEtBK0tLdU1EUWYzWVNwYUhhYlhYR2I1RzE3elNpcWRyMWc2VFNtczBXSGh2RXo1a09MaE9pUlFldkJZV3dqMTo6ticbtXB4eiLBJEZb748AQg==', 'T1ZjQUpWRWs3M3pwZXRUbU0wampPZz09Ojq5vRmpCcf4q/g2+E8F0Lgt', '', '', '', 'Registration and screening of potential clients for food aid', 'contract', 'Not in detail but in broad terms everything about: Name, address, date of birth, income and expenses fixed costs and family composition', 'New client applications', 'Intake volunteers, board members, Municipality of Almere', 'In practice 2 to 5 years after termination of assistance', 'high', 'Secured application access starts via a NAS, this should receive limited access at smb3 level to comply with access restriction, logging, backup, personal authorization,', 'Special training, limited access, four-eyes principle when onboarding new colleagues', 'yes', 'unknown', 'none', '', '2026-02-09 10:53:38', '2026-05-08 08:11:38', '2026-08-06', 1, 100000006, 'administration', 'active', '', 'in_progress'),
(200000012, 'No', 'No', 'Newsletters, Marketing campaigns and customer communication', '', '', '', '', '', '', '', '', 'Sending newsletters and updates', 'consent', 'Name via Email address, email address, communication preferences', 'Donors, volunteers, interested parties', 'Volunteers, communication team', 'As long as consent is valid (max 3 years)', 'low', 'Double opt-in, unsubscribe links', 'Periodic consent checks', 'yes', 'no', 'none', '', '2026-02-11 09:20:36', '2026-07-06 10:34:40', '2027-07-06', 1, 100000006, 'administration', 'active', '', 'in_progress'),
(200000013, 'No', 'No', 'Accounting and processing volunteer expense claims', '', '', '', '', '', '', '', '', 'Accounting and processing volunteer expense claims', 'legal_obligation', 'Name, bank details, transaction data, invoice data', 'Volunteers, suppliers, employees', 'Treasurer, accountant, tax authorities', '7 years (fiscal)', 'medium', 'Encrypted online financial software', 'Segregation of duties, four-eyes principle', 'yes', 'unknown', 'none', '', '2026-02-11 09:48:31', '2026-02-18 10:08:14', '2026-08-17', 1, 1, 'administration', 'active', '', 'in_progress'),
(200000014, 'No', 'Yes', 'Donor registration and donation administration', '', '', '', '', '', '', '', '', 'Registration of donors and processing of financial donations', 'consent', 'Name, address, contact details, bank details, donation history', 'Donors', 'Treasurer, accounting', '7 years after last donation', 'medium', 'Secure online bank transactions processed by Rabobank', 'Separation of donation and client data', 'yes', 'unknown', 'none', '', '2026-02-11 09:56:24', '2026-02-26 10:05:47', '2026-08-10', 1, 1, 'administration', 'active', '', 'in_progress'),
(200000015, 'No', 'No', 'Processing of clothing purchases internal administration and receipt', '', '', '', '', '', '', '', '', 'Registration of sold clothing sales to generate a receipt and to book internal money, provides balance.', 'legitimate_interests', 'test', 'test', 'test', 'test', 'medium', 'test', 'test', 'no', 'unknown', 'none', '', '2026-02-16 09:53:33', '2026-02-18 09:52:26', '2026-08-17', 1, 1, 'administration', 'active', 'test', 'not_required'),
(200000016, 'No', 'No', 'Processing of furniture and white goods purchases internal administration and transport', '', '', '', '', '', '', '', '', 'Clients using furniture and white goods provided with transport and the administration of this in a database', 'legitimate_interests', 'Name, address, transport date, type of items, balance', 'Clients, volunteers', 'VLA employees, clothing bank volunteers', '1 year after provision', 'low', 'Separate registration system, access restrictions', 'Minimal data collection, direct deletion', 'no', 'unknown', 'none', '', '2026-02-16 10:18:49', '2026-05-15 06:35:53', '2027-05-15', 1, 100000006, 'administration', 'active', 'Clients may use a balance per month provision. Because they are in need, we help', 'not_required'),
(200000017, 'No', 'Yes', 'Incident registration and safety notifications', '', '', '', '', '', '', '', '', 'Registration of safety incidents and undesirable behavior', 'legitimate_interests', 'Name of involved parties, incident description, witness statements', 'Clients, volunteers, visitors', 'Safety coordinator, board, police', '2 years after incident resolution', 'medium', 'Secured incident database, logging', 'Incident reporting protocol, limited access', 'no', 'unknown', 'none', '', '2026-02-16 10:26:16', '2026-02-18 10:20:35', '2026-08-15', 1, 1, 'administration', 'active', 'Ensuring safety of personnel and visitors', 'not_required'),
(200000018, 'No', 'No', 'Supermarket campaigns - collaboration with local supermarkets and suppliers', '', '', '', '', '', '', '', '', 'Online intake where people help with collecting food packages for food bank clients at local supermarkets.', 'consent', 'First name, middle name, last name, mobile, email address', 'Volunteers', 'coordinator, collection team', '3 years after termination of collaboration', 'low', '.', '.', 'no', 'unknown', 'none', '', '2026-02-16 10:28:39', '2026-05-15 06:34:44', '2027-05-15', 1, 100000006, 'administration', 'active', '.', 'not_required'),
(200000019, 'No', 'No', 'Transport arrangement for delivery of food packages to less mobile clients', '', '', '', '', '', '', '', '', 'Transport of food packages to clients with limited mobility. For which the food bank delivers food packages to homes.', 'contract', 'Name, address, mobility limitation', 'Clients with transport needs', 'Transport volunteers, coordinators', '6 months after last trip', 'medium', 'Encrypted planning software', 'Minimal data for drivers', 'no', 'unknown', 'none', '', '2026-02-16 10:38:18', '2026-02-18 09:47:20', '2026-08-17', 1, 1, 'administration', 'active', '', 'not_required'),
(200000020, 'No', 'Yes', 'Emergency contacts registration', '', '', '', '', '', '', '', '', 'Storing emergency contacts for clients and volunteers', 'vital_interests', 'Name, relationship, phone number', 'Clients and volunteers', 'Coordinators, security personnel', '1 year after termination of relationship', 'medium', 'Separate encrypted database', 'Only accessible in emergencies', 'no', 'unknown', 'none', '', '2026-02-16 10:40:01', '2026-02-16 10:40:01', '2026-08-15', 1, 1, 'administration', 'active', '', 'not_required'),
(200000021, 'No', 'No', 'Security of personnel and customers via CCTV surveillance', '', '', '', '', '', '', '', '', 'Theft prevention, personnel and customer safety, shoplifting registration', 'legitimate_interests', 'Timestamps, theft incidents', 'Customers, employees, visitors', 'Board, store management, police if theft', '4 weeks (unless incident)', 'high', 'Secure storage, access control, privacy masking, separate incident database', 'Clear signage, strict access procedure for theft images, security training', 'no', 'unknown', 'none', '', '2026-02-16 10:52:34', '2026-07-06 10:32:09', '2026-10-04', 1, 100000006, 'administration', 'active', 'Prevention of shoplifting and protection of discounted prices', 'not_required'),
(200000022, 'No', 'Yes', 'Recruitment and selection with attention to diversity', '', '', '', '', '', '', '', '', 'Vacancy process, application assessment, diversity monitoring', 'contract', 'CV, motivation letter, references, diversity data (anonymous), assessments', 'Applicants', 'HR, food bank board', '4 weeks after rejection (unless consent for extension)', 'medium', '.', 'Standardized retention periods, separate processing of diversity data', 'no', 'unknown', 'none', '', '2026-02-16 10:59:48', '2026-02-18 10:55:32', '2026-08-15', 1, 1, 'administration', 'active', '', 'not_required'),
(200000023, 'No', 'No', 'Registration of occupational accidents, sick leave and safety training according to CAO and Arbowet', '', '', '', '', '', '', '', '', 'Registration of accidents and near-accidents', 'legal_obligation', 'Personal data, accident description, medical data, prevention plan', 'Employees, visitors', 'HR, occupational health service, works council, prevention officer, CAO committee', '10 years after accident', 'medium', 'Secured incident database with CAO fields, encryption', 'Mandatory reporting according to CAO, limited access, works council involvement', 'no', 'unknown', 'none', '', '2026-02-16 11:01:53', '2026-07-10 07:46:13', '2027-01-06', 1, 100000006, 'administration', 'active', '', 'not_required'),
(200000024, 'No', 'No', 'WiFi tracking internal wireless network', '', '', '', '', '', '', '', '', 'Anonymous tracking of personnel via WiFi for inventory after a security incident.', 'consent', 'MAC address, hostnames', 'Volunteers, employees', 'ICT', 'few minutes', 'medium', 'encryption over transport, unknown to tplink administrator', 'ict policy document', 'no', 'unknown', 'none', '', '2026-02-16 11:18:17', '2026-02-18 09:46:37', '2026-08-17', 1, 1, 'administration', 'active', '', 'not_required'),
(200000025, 'No', 'Yes', 'Safety procedures and emergency response (BHV) registration', '', '', '', '', '', '', '', '', 'Registration of emergency response officers (BHV\'ers) and safety procedures', 'legal_obligation', 'Name, BHV certificate, training data, contact details', 'BHV\'ers, employees with safety functions', 'Board, Safety Coordinator, HR, supervisors, emergency services during incidents', '5 years after end of function', 'medium', 'BHV Folder', 'Protocol for safety information, strict access control, regular updates', 'no', 'unknown', 'none', '', '2026-02-16 11:21:58', '2026-02-18 10:55:51', '2026-08-15', 1, 1, 'administration', 'active', '', 'not_required'),
(200000027, 'No', 'No', 'Registration of occupational accidents according to CAO and Arbowet', '', '', '', '', '', '', '', '', 'Registration of accidents and near-accidents', 'legal_obligation', 'Personal data, accident description, medical data, prevention plan', 'Employees, customers', 'Board, Occupational health physician', '10 years after accident', 'medium', 'Multi-folder in secure cabinet with lock', 'Mandatory reporting according to CAO, limited access, works council involvement', 'yes', 'unknown', 'none', '', '2026-02-23 10:18:13', '2026-03-04 10:28:22', '2026-08-31', 100000006, 100000006, 'administration', 'active', '', 'in_progress'),
(200000028, 'No', 'No', 'Reintegration and sick leave guidance', '', '', '', '', '', '', '', '', 'Guidance of sick employees and reintegration', 'legal_obligation', 'Medical data, sick leave history, reintegration plan, CAO protocols', 'Sick employees', 'Board, HR, company doctor, supervisors, works council sick leave committee', '2 years after end of sick leave', 'high', 'Multi-folder, secure cabinet with lock', 'Need to know basis, medical confidentiality, works council involvement', 'yes', 'unknown', 'none', '', '2026-02-23 10:22:48', '2026-02-26 10:03:26', '2026-05-27', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000029, 'No', 'Yes', 'Complaint handling', '', '', '', '', '', '', '', '', 'Handling questions and complaints', 'contract', 'Name, contact details, complaint description, correspondence', 'Customers', 'Secretariat', '2 years after handling', 'low', 'Data minimization for customer handling, registration in word per day. Desired is that in the future this becomes a php system where one works with a form and prints it per situation and processes it in a multi-folder stored in a locked cabinet.', 'See Technical Measures.', 'no', 'unknown', 'none', '', '2026-02-23 10:29:04', '2026-02-23 10:29:04', '2027-02-23', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000030, 'No', 'No', 'Social media monitoring and engagement reputation management', '', '', '', '', '', '', '', '', 'Following own social media for reputation management and feedback', 'legitimate_interests', 'Facebook social media profile, messages, interactions with interested parties, Social media posts, usernames, sentiment analysis, engagement metrics', 'Social media users, stakeholders, customers, critics', 'Relationship management, ICT', '2 years', 'low', 'Processing Agreement with Third Party,', 'Actually protocol for dealing with interested parties', 'no', 'unknown', 'none', 'Standard Contractual Clauses Facebook', '2026-02-23 10:32:27', '2026-07-10 09:46:13', '2027-07-10', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000031, 'No', 'No', 'Processing of travel expense claims and expense reimbursements', '', '', '', '', '', '', '', '', 'Expense claims or advances for internal payments', 'contract', 'Transactions, expense receipt, online payment, cash payments, tickets, travel expense reimbursement', 'Employees', 'Board, Financial Administration', '7 years (fiscal)', 'medium', 'Multi-folder in secure cabinet with lock, limited access, online transaction with bank software secured encryption on connection', 'Internal expense policy', 'no', 'unknown', 'none', '', '2026-02-23 10:36:44', '2026-07-10 07:52:04', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000033, 'No', 'No', 'Payment processing at food bank checkout', '', '', '', '', '', '', '', '', 'Transaction processing of fictional payments of supermarket items.', 'contract', 'Payment card, transaction amount, timestamp, items', 'Customers', 'IT, card issuance, Elicash tool', '13 months (chargeback period), fiscal 7 years', 'high', 'To be investigated', 'To be investigated', 'yes', 'unknown', 'none', '', '2026-02-23 10:52:09', '2026-02-26 09:48:43', '2026-05-24', 100000006, 100000006, 'administration', 'active', '', 'in_progress'),
(200000034, 'Yes', 'Yes', 'Supplier inventory management and supplier administration', '', '', '', '', '', '', '', '', 'Management of supplier data and procurement processes', 'contract', 'Supplier contact details, bank details, contracts, order history', 'Suppliers', 'Procurement department, logistics, administration, distribution centers', '7 years after end of relationship (fiscal)', 'low', 'Secured supplier ordering system', 'Segregation of duties, control procedures', 'no', 'unknown', 'none', '', '2026-02-23 10:59:05', '2026-02-23 10:59:05', '2027-02-23', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000036, 'No', 'No', 'Online donations via the voedselbankalmere website and third-party Mollie online payment bank', '', '', '', '', '', '', '', '', 'Online donations are processed by Mollie online payment bank', 'contract', 'Name, Email address, amount', 'Donors', 'Finance and ICT', '7 years (fiscal)', 'medium', 'm2fa on Mollie online bank', 'Limited access, Transport protocol,', 'no', 'unknown', 'none', '', '2026-05-15 06:46:28', '2026-05-15 06:46:28', '2026-11-11', 100000006, 100000006, 'donations', 'active', '', 'not_required'),
(200000037, 'No', 'No', 'Corporate email', '', '', '', '', '', '', '', '', 'Corporate email, Archiving email for compliance', 'contract', 'Email content, contact details, attachments, metadata', 'Employees, external contacts, All email users, compliance officer', 'IT management, compliance during investigation, Legal department, external auditors (if necessary)', '7 years (fiscal), longer for ongoing matters', 'medium', 'Encryption in transit and at rest, spam filtering, Encrypted email archive, retention management', 'Acceptable Use Policy, awareness training, Email policy, training correct email use', 'no', 'unknown', 'none', '', '2026-05-15 06:49:45', '2026-05-15 06:52:50', '2026-11-11', 100000006, 100000006, 'other', 'active', '', 'not_required'),
(200000038, 'No', 'Yes', 'Card issuance and client administration of the balance on the cards', '', '', '', '', '', '', '', '', 'Processing of name and address data for the assignment of cards to purchase groceries in the store. Balance allocation to client name and address data but also volunteers with their volunteer card.', 'contract', 'Name, address, city, postal code, card balance, card category', 'Client contact details', 'Clients, volunteers', 'Deactivated or inactive cards after 2 years', 'medium', 'Authentication', 'Periodic checks', 'yes', 'unknown', 'none', '', '2026-05-15 08:00:23', '2026-06-02 08:31:00', '2026-11-29', 100000006, 100000006, 'administration', 'active', '', 'in_progress'),
(200000039, 'No', 'No', 'Registration of emergency response officers (BHV\'ers), drills and certification', '', '', '', '', '', '', '', '', 'Registration of emergency response officers (BHV\'ers), drills and certification', 'legitimate_interests', 'First name, Last name, prefix', 'personal data', 'management', '2 years after termination', 'low', 'login in Access.', 'Segregation of duties', 'no', 'unknown', 'none', '', '2026-07-06 10:10:00', '2026-07-06 10:11:55', '2027-07-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000040, 'No', 'No', 'Registering and managing employee training and development', '', '', '', '', '', '', '', '', 'Registering and managing employee training and development', 'legitimate_interests', 'Employee data, training history, certificates, assessments, development plans', 'Employees, trainers, coaches', 'HR development, managers, employees themselves', '5 years after termination of employment', 'low', 'Learning management system with security, encryption of personal development data', 'Access to own data, privacy by design in development systems, opt-out possibilities', 'no', 'unknown', 'none', '', '2026-07-06 10:19:58', '2026-07-06 10:19:58', '2027-07-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000041, 'No', 'No', 'Internal and external audit processes and control monitoring', '', '', '', '', '', '', '', '', 'Internal and external audit processes and control monitoring', 'legal_obligation', 'Audit reports, findings, action plans, evidence documents, control tests', 'Auditors, process owners, management, control operators', 'Internal audit, external auditors, DNB, compliance', '7 years after audit completion', 'high', 'Internal and external audit processes and control monitoring', 'Internal and external audit processes and control monitoring', 'no', 'unknown', 'none', '', '2026-07-06 10:23:10', '2026-07-10 08:54:39', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000042, 'No', 'No', 'Processing of financial transactions and accounting processes', '', '', '', '', '', '', '', '', 'Processing of financial transactions and accounting processes', 'legitimate_interests', 'Processing of financial transactions and accounting processes', 'Processing of financial transactions and accounting processes', 'Processing of financial transactions and accounting processes', '7 years (fiscal)', 'medium', 'Processing of financial transactions and accounting processes', 'Processing of financial transactions and accounting processes', 'no', 'unknown', 'none', '', '2026-07-10 07:26:09', '2026-07-10 07:26:09', '2027-01-06', 100000006, 100000006, 'administration', 'active', 'Processing of financial transactions and accounting processes', 'not_required'),
(200000043, 'No', 'No', 'Monitoring social media and online reviews for international reputation management', '', '', '', '', '', '', '', '', 'Monitoring social media and online reviews for international reputation management', 'legitimate_interests', 'Monitoring social media and online reviews for international reputation management', 'Monitoring social media and online reviews for international reputation management', 'Monitoring social media and online reviews for international reputation management', '2 years after account deletion', 'medium', 'Monitoring social media and online reviews for international reputation management', 'Monitoring social media and online reviews for international reputation management', 'no', 'unknown', 'none', '', '2026-07-10 07:43:13', '2026-07-10 07:43:13', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000044, 'No', 'No', 'Regular business data backups and recovery procedures', '', '', '', '', '', '', '', '', 'Regular business data backups and recovery procedures', 'legitimate_interests', 'Regular business data backups and recovery procedures', 'Regular business data backups and recovery procedures', 'Regular business data backups and recovery procedures', 'Regular business data backups and recovery procedures', 'medium', 'Regular business data backups and recovery procedures', 'Regular business data backups and recovery procedures', 'no', 'unknown', 'none', '', '2026-07-10 07:45:36', '2026-07-10 07:45:36', '2027-01-06', 100000006, 100000006, 'administration', 'active', 'Regular business data backups and recovery procedures', 'not_required'),
(200000045, 'No', 'No', 'Registration and reporting of security incidents and data breaches', '', '', '', '', '', '', '', '', 'Registration and reporting of security incidents and data breaches', 'legitimate_interests', 'Registration and reporting of security incidents and data breaches', 'Registration and reporting of security incidents and data breaches', 'Registration and reporting of security incidents and data breaches', 'Registration and reporting of security incidents and data breaches', 'medium', 'Registration and reporting of security incidents and data breaches', 'Registration and reporting of security incidents and data breaches', 'no', 'unknown', 'none', '', '2026-07-10 07:47:34', '2026-07-10 07:47:34', '2027-01-06', 100000006, 100000006, 'administration', 'active', 'Registration and reporting of security incidents and data breaches', 'not_required'),
(200000046, 'No', 'No', 'Registration and processing of RID data', '', '', '', '', '', '', '', '', 'Registration and processing of RID data', 'legitimate_interests', 'Registration and processing of RID data', 'Registration and processing of RID data', 'Registration and processing of RID data', 'Registration and processing of RID data', 'medium', 'Registration and processing of RID data', 'Registration and processing of RID data', 'no', 'unknown', 'none', '', '2026-07-10 07:48:37', '2026-07-10 07:48:37', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000047, 'No', 'No', 'Registration of employee training, certificates and competencies', '', '', '', '', '', '', '', '', 'Registration of employee training, certificates and competencies', 'legitimate_interests', 'Registration of employee training, certificates and competencies', 'Registration of employee training, certificates and competencies', 'Registration of employee training, certificates and competencies', 'Registration of employee training, certificates and competencies', 'medium', 'Registration of employee training, certificates and competencies', 'Registration of employee training, certificates and competencies', 'no', 'unknown', 'none', '', '2026-07-10 07:49:49', '2026-07-10 07:49:49', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000048, 'No', 'No', 'Handling customer questions, fault reports, appointment scheduling, complaint handling', '', '', '', '', '', '', '', '', 'Handling customer questions, fault reports, appointment scheduling, complaint handling', 'contract', 'Customer contact details, communication history, preferences, complaint details', 'Customers with questions, fault reports, complainants', 'Call center employees, technicians, quality management', '2 years after last contact', 'medium', 'Encrypted CRM system, secured call recordings, access restrictions, call logging', 'Privacy training for employees, clear scripts, quality controls, data minimization', 'no', 'unknown', 'none', '', '2026-07-10 07:56:55', '2026-07-10 08:51:55', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000049, 'No', 'No', 'Analysis of website usage and cookie management for optimization', '', '', '', '', '', '', '', '', 'Analysis of website usage and cookie management for optimization', 'consent', 'IP address, browser data, page views, click behavior, cookie IDs, device info', 'Website visitors, online service users, customers', 'Web analytics team, marketing, UX designers, IT', '14 months (analytics standard)', 'low', 'Cookie consent management, IP anonymization, tracking restrictions, encryption', 'Privacy by design, cookie policy compliance, regular audits', 'no', 'unknown', 'none', '', '2026-07-10 07:59:42', '2026-07-10 08:53:20', '2027-07-10', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000050, 'No', 'No', 'Management of company smartphones and tablets', '', '', '', '', '', '', '', '', 'Management of company smartphones and tablets', 'legitimate_interests', 'Management of company smartphones and tablets', 'Device ID, location, user data, company app data', 'Employees with company devices', 'Until device return, then wipe', 'high', 'MDM software, encryption, remote wipe, sandboxing', 'Mobile working policy, secure usage training', 'no', 'unknown', 'none', '', '2026-07-10 08:05:47', '2026-07-10 08:05:47', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000051, 'No', 'Yes', 'Management of client contacts and relationship management', '', '', '', '', '', '', '', '', 'Management of client contacts and relationship management', 'legitimate_interests', 'Contact details, communication history, preferences, project history', 'Clients, relations', 'Account managers, marketing, management', '5 years after last contact', 'medium', 'Access restrictions per role, encryption, regular backups', 'Training for account managers, privacy by design in CRM', 'no', 'unknown', 'none', '', '2026-07-10 08:09:15', '2026-07-10 08:09:15', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000052, 'No', 'No', 'Tracking company vehicles for efficiency, safety management and equipment tracking', '', '', '', '', '', '', '', '', 'Tracking company vehicles for efficiency and safety', 'legitimate_interests', 'Location data, driving behavior, fuel consumption, driver data', 'Employees with company vehicles', 'Logistics, management, leasing company', '3 months location data, 2 years other data', 'medium', 'Anonymization where possible, limited storage duration', 'Clear communication to employees, policy rules', 'no', 'unknown', 'none', '', '2026-07-10 08:12:23', '2026-07-10 08:12:51', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000053, 'No', 'No', 'Management of key account relationships, contracts and agreements', '', '', '', '', '', '', '', '', 'Management of key account relationships and contracts', 'contract', 'Company data, contact persons, contract documents, SLAs, pricing agreements, contract data, signatories, terms, changes', 'Key accounts (large corporate clients), contract partners, signatories, legal counsel', 'Key account managers, finance, legal, contract management, legal affairs, procurement', '10 years after contract termination', 'high', 'Secure document management, encryption, access control, contract encryption, Contract management system, encrypted contracts, digital signatures', 'Contract lifecycle management, strict confidentiality clauses, limited access, Contract procedures, approval workflows, archiving', 'yes', 'unknown', 'none', '', '2026-07-10 08:15:44', '2026-07-10 08:59:10', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000054, 'No', 'Yes', 'Management of fire safety systems and fire drills', '', '', '', '', '', '', '', '', 'Management of fire safety systems and fire drills', 'legal_obligation', 'Fire officers, drill participants, system maintainers', 'Company fire brigade, external fire services, maintenance contractors', 'HSE, facility management, local fire department', '10 years', 'medium', 'Encrypted fire safety management system, access control critical systems, logging', 'Fire safety procedures, regular drills, system maintenance', 'no', 'unknown', 'none', '', '2026-07-10 08:24:08', '2026-07-10 08:24:08', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000055, 'No', 'No', 'Management of fuel consumption and fuel cards', '', '', '', '', '', '', '', '', 'Management of fuel consumption and fuel cards', 'legitimate_interests', 'Driver identification, fuel transactions, vehicle data, mileage readings', 'Drivers', 'Logistics, finance, management', '7 years for fiscal purposes', 'medium', 'Fuel card system with authentication, transaction encryption', 'Control procedures for fuel transactions', 'no', 'unknown', 'none', '', '2026-07-10 08:26:58', '2026-07-10 08:26:58', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000056, 'No', 'No', 'Management of digital and physical archives', '', '', '', '', '', '', '', '', 'Management of digital and physical archives', 'legitimate_interests', 'All categories of personal data (depending on document type)', 'All data subjects', 'Archive manager, various departments', 'Varying per document type (2-10 years)', 'medium', 'Encrypted archive storage, access control, logging', 'Destruction protocol for outdated documents', 'no', 'unknown', 'none', '', '2026-07-10 08:31:21', '2026-07-10 08:31:21', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000057, 'No', 'Yes', 'Management of digital workplaces and devices', '', '', '', '', '', '', '', '', 'Management of digital workplaces and devices', 'legitimate_interests', 'Device information, user profiles, application data, security logs', 'Employees', 'IT department, security team, device suppliers', '1 year after device return', 'medium', 'MDM solution, encryption, remote wipe, logging', 'Acceptable use policy, privacy by design, training', 'no', 'unknown', 'none', '', '2026-07-10 08:33:07', '2026-07-10 08:33:07', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000058, 'No', 'No', 'Management of outstanding receivables and collection procedures', '', '', '', '', '', '', '', '', 'Management of outstanding receivables and collection procedures', 'legitimate_interests', 'Customer data, payment arrears, collection status, correspondence', 'Customers', 'Credit management, collection agency, legal department', '7 years after settlement', 'medium', 'Credit management system with access restrictions', 'Automated reminders, escalation procedures', 'no', 'unknown', 'none', '', '2026-07-10 08:39:33', '2026-07-10 08:39:33', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000059, 'No', 'No', 'Management of personnel data, salaries and employment conditions', '', '', '', '', '', '', '', '', 'Management of personnel data, salaries and employment conditions', 'legal_obligation', 'Personal data, SSN, salary data, bank account number, contracts', 'Employees, payroll administrators, managers', 'HR department, payroll provider, tax authorities, banks', '7 years after employment (fiscal)', 'high', 'encryption, two-factor authentication, secured payments', 'Segregation of duties, four-eyes principle, regular audits', 'yes', 'unknown', 'none', '', '2026-07-10 08:41:33', '2026-07-10 08:41:33', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000060, 'No', 'No', 'Management of inventories and warehouse activities', '', '', '', '', '', '', '', '', 'Management of inventories and warehouse activities', 'contract', 'Warehouse employee data, access logs, picking orders, inventory', 'Warehouse personnel, forklift drivers, inventory clerks', 'Logistics management, warehouse supervision, production planning', '2 years after activity', 'low', 'security, barcode/RFID encryption, access control systems', 'Warehouse protocols, safety procedures, regular counting', 'no', 'unknown', 'none', '', '2026-07-10 08:45:47', '2026-07-10 08:45:47', '2027-07-10', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000061, 'No', 'No', 'Management of insurance policies', '', '', '', '', '', '', '', '', 'Management of insurance policies, premium calculation and collection', 'contract', 'Name/address data, SSN, date of birth, policy data, premium amounts, payment data', 'Insured parties, premium payers, beneficiaries', 'Administration, collection agencies, banks, intermediaries', '7 years after policy termination (fiscal)', 'high', 'Encrypted databases, two-factor authentication, secure payment processing', 'Strict access control, segregation of duties, regular reconciliations', 'no', 'unknown', 'none', '', '2026-07-10 08:47:23', '2026-07-10 08:47:23', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000062, 'No', 'No', 'Managing and responding to cybersecurity incidents', '', '', '', '', '', '', '', '', 'Managing and responding to cybersecurity incidents', 'legitimate_interests', 'Log data, incident details, affected systems, response actions', 'IT personnel, security personnel, affected individuals', 'CERT teams, law enforcement, insurance providers', '2 years after incident closure', 'high', 'SIEM systems, forensic tools, encrypted incident logs', 'Incident response plan, communication protocols, information sharing procedures', 'yes', 'unknown', 'none', '', '2026-07-10 08:50:22', '2026-07-10 08:50:22', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000063, 'No', 'No', 'Managing user identities and access rights to systems', '', '', '', '', '', '', '', '', 'Managing user identities and access rights to systems', 'legal_obligation', 'Usernames, authentication data, role assignments, access logs, approval workflows', 'Employees, external users, system administrators', 'IAM team, system administrators, managers', '7 years after account deletion', 'high', 'Multi-factor authentication, privileged access management, identity governance', 'Principle of least privilege, regular access reviews, segregation of duties', 'yes', 'unknown', 'none', 'Multi-factor authentication, privileged access management, identity governance\r\nPrinciple of least privilege, regular access reviews, segregation of duties', '2026-07-10 08:56:04', '2026-07-10 08:56:04', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000064, 'Yes', 'No', 'Managing work orders and execution', '', '', '', '', '', '', '', '', 'Managing work orders and execution', 'contract', 'Work order details, execution data, progress, invoicing', 'Contractors, employees, clients', 'Execution management, project administration, invoicing', '7 years for administrative purposes', 'medium', 'Work order management system, encrypted data, access control', 'Execution protocols, quality control, invoicing procedures', 'yes', 'unknown', 'none', '', '2026-07-10 09:02:05', '2026-07-10 09:02:05', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000065, 'No', 'No', 'Physical security and access control', '', '', '', '', '', '', '', '', 'Security of warehouses and access registration of personnel/visitors', 'legitimate_interests', 'Name, employee number, access times, location, visitor data\r\nAccess passes, visitor registration, camera images, access times', 'Employees, visitors, suppliers, security personnel', 'Security, HR, facility management', '30 days camera, 1 year access logs', 'medium', 'Access pass systems, CCTV (separate DPIA), logging\r\nEncrypted access systems, privacy masking cameras, secure storage', 'Limited access logs, clear CCTV signage\r\nSecurity policy, access protocols, transparency about monitoring', 'yes', 'unknown', 'none', '', '2026-07-10 09:09:36', '2026-07-10 09:39:53', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000066, 'No', 'No', 'Accounting and invoicing to customers, payments and expense claims', '', '', '', '', '', '', '', '', 'Accounting and invoicing to customers', 'legal_obligation', 'Name, address, VAT number, bank details, payment history\r\nPayment data, invoice data, bank accounts, transactions', 'Customers, suppliers, personnel', 'Accountants, banks, tax authorities, financial administration, accountants', '7 years (fiscal retention obligation)', 'medium', 'Encryption of financial data, access control, secure payment systems', 'Segregation of duties, four-eyes principle, internal controls, segregation of duties, audits', 'yes', 'unknown', 'none', '', '2026-07-10 09:14:19', '2026-07-10 09:25:41', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000067, 'No', 'No', 'Accounting, tax returns and financial reporting in various countries', '', '', '', '', '', '', '', '', 'Accounting, tax returns and financial reporting in various countries', 'legal_obligation', 'Customer/supplier company data internationally, transaction data, financial overviews per country', 'Customers, suppliers, employees (salary)', 'Accountants per country, international accountants, tax authorities, international banks', '7-10 years (fiscal retention obligation per country)', 'high', 'Encrypted financial software per country, access control, logging, MFA, international consolidation security', 'International segregation of duties, four-eyes principle, regular audits per country, training', 'yes', 'yes', 'none', '', '2026-07-10 09:20:17', '2026-07-10 09:20:17', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000068, 'No', 'No', 'Maintaining and managing personnel files, professional competence and certifications', '', '', '', '', '', '', '', '', 'Maintaining and managing personnel files (10 years after employment)\r\nCertificates, diplomas, recertification data, assessments (5 years after end of employment)', 'contract', 'Personal data, contracts, assessments, disciplinary matters, sick leave', 'Employees', 'HR department, direct supervisors, company doctor, certification bodies', '10 years after employment', 'medium', 'Secured HR systems, role-based access control, audit logs', 'Need-to-know basis, confidentiality agreements', 'yes', 'unknown', 'none', '', '2026-07-10 09:21:48', '2026-07-10 09:23:11', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000069, 'No', 'No', 'Compliance monitoring, audits, whistleblower system', '', '', '', '', '', '', '', '', 'Compliance monitoring, audits, whistleblower system worldwide', 'legal_obligation', 'Whistleblower reports, audit findings, compliance data', 'Employees, suppliers, customers (incidents)', 'Compliance team, audit, board of directors', '7 years (compliance), 5 years (whistleblower anonymous)', 'high', 'Encryption, anonymous reporting tools, strict access control', 'Whistleblower protection, strict access rights, audit trails', 'yes', 'unknown', 'none', '', '2026-07-10 09:28:54', '2026-07-10 09:28:54', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000070, 'No', 'No', 'Contract management, procurement processes, supplier management, tenders', '', '', '', '', '', '', '', '', 'Contract management, procurement processes, supplier management, tenders', 'contract', 'Supplier data, contact persons, contract documents, performance data, payment data', 'Suppliers, contractors, service providers, advisors', 'Procurement department, legal department, project teams, finance', '7 years after contract termination (fiscal)', 'medium', 'Secure contract management system, encrypted document storage, digital signatures, access control', 'Vendor management procedures, due diligence processes, regular performance reviews, compliance monitoring', 'no', 'unknown', 'none', '', '2026-07-10 09:30:51', '2026-07-10 09:30:51', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000071, 'No', 'No', 'Archiving of historical documents and project files', '', '', '', '', '', '', '', '', 'Digitalization and archiving of historical documents and project files', 'legal_obligation', 'Historical documents, project archives, correspondence, technical drawings', 'Former employees, historical stakeholders, researchers', 'Archive service, legal department, historical researchers', 'Permanent (historical archive)', 'medium', 'Encrypted archives, digital preservation systems, access controls', 'Archiving policy, access protocols, historical research guidelines', 'yes', 'unknown', 'none', '', '2026-07-10 09:34:38', '2026-07-10 09:34:38', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000072, 'No', 'No', 'Periodic health checks for physical work', '', '', '', '', '', '', '', '', 'Periodic health checks for physical work', 'legal_obligation', 'Medical data, work ability, health test', 'employees', 'Company doctor, HR, supervisors', '2 years after departure', 'high', 'Separate secured database, encryption', 'Strict access restrictions, separate HR officer', 'yes', 'unknown', 'none', '', '2026-07-10 09:49:49', '2026-07-10 09:49:49', '2026-10-08', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000073, 'No', 'No', 'Personnel planning, location determination, work orders, reporting', '', '', '', '', '', '', '', '', 'Personnel planning, location determination, work orders, reporting', 'contract', 'Personnel location data, work orders, customer visits, travel times', 'Service employees, planners', 'Operations, planning, customer service, managers', '2 years after work order completion', 'medium', 'GPS encryption, secure field service apps, limited real-time tracking', 'Clear communication to employees, privacy by design planning, anonymization for analysis', 'no', 'unknown', 'none', '', '2026-07-10 09:53:40', '2026-07-10 09:53:40', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required'),
(200000074, 'No', 'No', 'Planning work schedules, recording hours worked and leave', '', '', '', '', '', '', '', '', 'Planning work schedules, recording hours worked and leave', 'contract', 'Name, function, availability, hours worked, leave requests, schedule', 'Employees, team leaders, planning staff', 'HR, branch management, payroll, team leaders', '2 years after registration', 'medium', 'Secured scheduling software, access control, logging, encryption', 'Transparency to employees, privacy by design, manager training', 'no', 'unknown', 'none', '', '2026-07-10 10:52:20', '2026-07-10 10:52:20', '2027-01-06', 100000006, 100000006, 'administration', 'active', '', 'not_required');

-- --------------------------------------------------------

--
-- Table structure for table `implementation_notes`
--

CREATE TABLE `implementation_notes` (
  `id` int(11) NOT NULL,
  `measure_id` int(11) NOT NULL,
  `note_text` text NOT NULL,
  `created_by` varchar(100) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `security_measures`
--

CREATE TABLE `security_measures` (
  `id` int(11) NOT NULL,
  `gdpr_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `system_changes`
--

CREATE TABLE `system_changes` (
  `id` int(11) NOT NULL,
  `table_name` varchar(100) NOT NULL,
  `record_id` int(11) NOT NULL,
  `action` enum('INSERT','UPDATE','DELETE','VIEW','EXPORT','LOGIN','LOGOUT','PRINT') NOT NULL,
  `old_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`old_data`)),
  `new_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`new_data`)),
  `changed_fields` text DEFAULT NULL,
  `changed_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `changed_by` int(11) NOT NULL,
  `user_ip` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `system_users`
--

CREATE TABLE `system_users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `full_name` varchar(100) DEFAULT NULL,
  `role` enum('admin','editor','viewer') DEFAULT 'viewer',
  `is_active` tinyint(1) DEFAULT 1,
  `last_login` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `failed_login_attempts` int(11) DEFAULT 0,
  `account_locked_until` datetime DEFAULT NULL,
  `two_factor_secret` varchar(255) DEFAULT NULL,
  `two_factor_enabled` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Data export for table `system_users`
--

INSERT INTO `system_users` (`id`, `username`, `password`, `email`, `full_name`, `role`, `is_active`, `last_login`, `created_at`, `updated_at`, `failed_login_attempts`, `account_locked_until`, `two_factor_secret`, `two_factor_enabled`) VALUES
(100000006, 'admin', '$2y$10$ifoYj1/m3mHWf5j27vIO2.ED5eEPCkQJ/aRV776aSHWDkrxYua./C', 'ict@voedselbankalmere.nl', 'System Administrator', 'admin', 1, '2026-07-10 11:17:50', '2026-02-18 10:09:50', '2026-07-10 09:17:50', 0, NULL, NULL, 0);

-- --------------------------------------------------------

--
-- Table structure for table `third_parties`
--

CREATE TABLE `third_parties` (
  `id` int(11) NOT NULL,
  `company_name` varchar(255) NOT NULL,
  `contact_person` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `phone` varchar(50) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `service_provided` text NOT NULL,
  `processing_agreement_signed` enum('yes','no','in_progress') DEFAULT 'no',
  `agreement_date` date DEFAULT NULL,
  `agreement_expiry_date` date DEFAULT NULL,
  `compliance_status` enum('compliant','non_compliant','review_needed') DEFAULT 'review_needed',
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Data export for table `third_parties`
--

INSERT INTO `third_parties` (`id`, `company_name`, `contact_person`, `email`, `phone`, `address`, `service_provided`, `processing_agreement_signed`, `agreement_date`, `agreement_expiry_date`, `compliance_status`, `created_by`, `created_at`, `updated_at`) VALUES
(3, 'Rabobank online payments', '', '', '', '', 'Bank transactions expense claims', 'yes', NULL, NULL, 'compliant', 1, '2026-02-11 09:50:15', '2026-02-11 09:50:15'),
(4, 'La Posta newsletters', '', '', '', '', 'Sending newsletters and updates', 'yes', NULL, NULL, 'compliant', 1, '2026-02-11 09:52:11', '2026-02-11 09:52:11'),
(5, 'Microsoft 365 online working', '', '', '', '', 'Online documents', 'no', NULL, NULL, 'review_needed', 1, '2026-02-11 09:53:55', '2026-02-11 09:53:55'),
(6, 'Mollie online donation bank', '', '', '', '', 'Donation of money via the voedselbankalmere website. The Mollie service is an online bank to collect donation money.', 'no', NULL, NULL, 'review_needed', 100000006, '2026-05-15 06:37:46', '2026-05-15 06:38:11');

--
-- Indexes for exported tables
--

--
-- Indexes for table `data_breaches`
--
ALTER TABLE `data_breaches`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `dpia_registrations`
--
ALTER TABLE `dpia_registrations`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_record_dpia` (`record_id`),
  ADD KEY `registered_by` (`registered_by`);

--
-- Indexes for table `gdpr_register`
--
ALTER TABLE `gdpr_register`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_risk_level` (`risk_level`),
  ADD KEY `idx_dpia_required` (`dpia_required`),
  ADD KEY `idx_international_transfers` (`is_international_data_transfers`);

--
-- Indexes for table `implementation_notes`
--
ALTER TABLE `implementation_notes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `measure_id` (`measure_id`);

--
-- Indexes for table `security_measures`
--
ALTER TABLE `security_measures`
  ADD PRIMARY KEY (`id`),
  ADD KEY `gdpr_id` (`gdpr_id`);

--
-- Indexes for table `system_changes`
--
ALTER TABLE `system_changes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `changed_by` (`changed_by`);

--
-- Indexes for table `system_users`
--
ALTER TABLE `system_users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `third_parties`
--
ALTER TABLE `third_parties`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for exported tables
--

--
-- AUTO_INCREMENT for table `data_breaches`
--
ALTER TABLE `data_breaches`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `dpia_registrations`
--
ALTER TABLE `dpia_registrations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=300000011;

--
-- AUTO_INCREMENT for table `gdpr_register`
--
ALTER TABLE `gdpr_register`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=200000075;

--
-- AUTO_INCREMENT for table `implementation_notes`
--
ALTER TABLE `implementation_notes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `security_measures`
--
ALTER TABLE `security_measures`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `system_changes`
--
ALTER TABLE `system_changes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=367;

--
-- AUTO_INCREMENT for table `system_users`
--
ALTER TABLE `system_users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=100000007;

--
-- AUTO_INCREMENT for table `third_parties`
--
ALTER TABLE `third_parties`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- Constraints for exported tables
--

--
-- Constraints for table `dpia_registrations`
--
ALTER TABLE `dpia_registrations`
  ADD CONSTRAINT `dpia_registrations_ibfk_1` FOREIGN KEY (`record_id`) REFERENCES `gdpr_register` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `dpia_registrations_ibfk_2` FOREIGN KEY (`registered_by`) REFERENCES `system_users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `implementation_notes`
--
ALTER TABLE `implementation_notes`
  ADD CONSTRAINT `implementation_notes_ibfk_1` FOREIGN KEY (`measure_id`) REFERENCES `security_measures` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `security_measures`
--
ALTER TABLE `security_measures`
  ADD CONSTRAINT `security_measures_ibfk_1` FOREIGN KEY (`gdpr_id`) REFERENCES `gdpr_register` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `system_changes`
--
ALTER TABLE `system_changes`
  ADD CONSTRAINT `system_changes_ibfk_1` FOREIGN KEY (`changed_by`) REFERENCES `system_users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;