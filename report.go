Skip to content
Search or jump to…
Pull requests
Issues
Marketplace
Explore
 
@wss-qa 
scm-scanner-automation
/
go-modules
Private
Code
Issues
2
Pull requests
Actions
Projects
Security
Insights
Settings
go-modules/report.go /
@wss-qa
wss-qa Add files via upload
Latest commit e1ffd12 18 days ago
 History
 1 contributor
326 lines (280 sloc)  10.4 KB
   
package insights

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	"github.com/miekg/dns"
)

// DetailedReport represents a detailed report, with an HTML email and a full
// report
type DetailedReport struct {
	teamName  string
	scanID    string
	teamID    string
	folder    string
	URL       string
	Email     string
	Risk      int
	conf      config.Config
	awsConfig *aws.Config
}

// NewDetailedReport  initializes and returns a new DetailedReport
func NewDetailedReport(configFile, teamName, scanID, teamID string) (*DetailedReport, error) {
	resources.Include()

	conf, err := config.ReadConfig(configFile)
	if err != nil {
		return nil, err
	}

	detailedReport := &DetailedReport{
		teamName: teamName,
		scanID:   scanID,
		teamID:   teamID,
		conf:     conf,
	}

	// Set default region for AWS config.
	if conf.S3.Region == "" {
		conf.S3.Region = "eu-west-1"
	}
	detailedReport.awsConfig = aws.NewConfig().WithRegion(conf.S3.Region).WithMaxRetries(3)
	if conf.S3.Endpoint != "" {
		detailedReport.awsConfig.WithEndpoint(conf.S3.Endpoint).WithS3ForcePathStyle(conf.S3.PathStyle)
	}

	return detailedReport, nil
}

// GenerateLocalFiles grabs data for a fiven scan ID from Vulcan Core and saves
// the HTML enauk and the  full report in a local folder
func (d *DetailedReport) GenerateLocalFiles() error {
	// Grabs scan data on Vulcan Core
	reportData, err := vulcan.GetReportData(d.conf, d.scanID)
	if err != nil {
		return err
	}
	// NOTE: Grouping is done using vulcan-groupie in the vulcan package.
	// reportData = groupVulnerabilitiesByTextSimilarity(reportData)

	buf, err := json.Marshal(reportData)
	if err != nil {
		return err
	}

	ioutil.WriteFile(d.teamName+".json", buf, 0600)

	// Assemble the folder name. The format is:	hex(sha256(teamName))/YYYY-MM-DD
	// The idea behind this is that if we use teams names as folder names, then
	// it would be easy to predict in which folders the reports are stored for
	// each team
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(d.teamName)))
	d.folder = filepath.Join(sha, reportData.Date)

	// Remove previously generated files and folders and then recreate them.
	err = d.cleanLocalFolders()
	if err != nil {
		return err
	}

	// Generate files for the Overview. The files will be stored in this way:
	// <scan-id>/
	//	  '
	//    '--<scan-id>-overview.html
	//	  '
	//    '--<public-bucket>/
	//	         '
	//           '--<hex(sha256(teamName))>/
	//	                '
	//                  '--<YYYY-MM-DD>/
	//                         '
	//                         '--<Most Vulnerable Assets>.png
	//                         '
	//                         '--<Impact Distribution>.png
	d.Email, err = report.GenerateOverview(d.conf, d.awsConfig, d.conf.General.ResourcesPath, d.folder, reportData, d.teamName, d.teamID, d.scanID)
	if err != nil {
		return err
	}

	// Generate files for the Full Report. The files will be stored in this way:
	// <scan-id>/
	//    '
	//    '--<private-bucket>/
	//           '
	//           '--<hex(sha256(teamName))>/
	//                  '
	//                  '--<YYYY-MM-DD>/
	//                         '
	//                         '--<scan-id>-full-report.html
	//                         '
	//                         '--<script>.js
	//
	// The result will be the the URL in which the Full Report will be available.
	// The Overview HTML will be generated pointing to this link.
	d.URL, err = report.GenerateFullReport(d.conf, d.awsConfig, d.conf.General.ResourcesPath, d.folder, reportData, d.teamName)
	if err != nil {
		return err
	}

	d.Risk = int(reportData.Risk)

	return nil
}

func (d *DetailedReport) cleanLocalFolders() error {
	err := os.RemoveAll(filepath.Join(d.conf.General.LocalTempDir, d.scanID))
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Join(d.conf.General.LocalTempDir, d.scanID, d.conf.S3.PublicBucket, d.folder), 0700)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Join(d.conf.General.LocalTempDir, d.scanID, d.conf.S3.PrivateBucket, d.folder), 0700)
	if err != nil {
		return err
	}

	return nil
}

func (d *DetailedReport) UploadFilesToS3() error {
	err := d.uploadBucket(d.conf.S3.PrivateBucket)
	if err != nil {
		return err
	}

	err = d.uploadBucket(d.conf.S3.PublicBucket)
	if err != nil {
		return err
	}

	log.Printf("overview: %v", d.Email)
	log.Printf("full report: %v", d.URL)

	return nil
}

func (d *DetailedReport) uploadBucket(bucket string) error {
	localPath := filepath.Join(d.conf.General.LocalTempDir, d.scanID, bucket, d.folder)
	fd, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer fd.Close()
	files, _ := fd.Readdir(-1)
	for _, file := range files {
		log.Printf("upload: %v/%v", bucket, filepath.Join(d.folder, file.Name()))
		err = d.uploadFile(bucket, filepath.Join(d.folder, file.Name()), localPath, file.Name())
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *DetailedReport) uploadFile(bucket, key, localPath, filename string) error {
	svc := s3.New(session.New(d.awsConfig))
	localFilename := filepath.Join(localPath, filename)
	contentType := mime.TypeByExtension(filepath.Ext(localFilename))
	body, err := ioutil.ReadFile(localFilename)
	if err != nil {
		return err
	}

	params := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	}

	_, err = svc.PutObject(params)
	if err != nil {
		return err
	}

	return nil
}

// groupVulnerabilitiesByTextSimilarity groups vulnerabilities by matching
// Summary and Recommendations.
// TODO: Consider moving this function to vulcan-groupie, if we find is interesting
// to continue grouping by Similarity.
func groupVulnerabilitiesByTextSimilarity(reportData *vulcan.ReportData) *vulcan.ReportData {
	// Iterate over reportData.Vulnerabilities and assemble an array of
	// vulcan vulnerabilties
	vulnStore := []*vulcan.Vulnerability{}
	for i := 0; i < len(reportData.Vulnerabilities); i++ {
		vulnStore = append(vulnStore, &reportData.Vulnerabilities[i])
	}

	// Iterate over vulcan vulnerabilties
	for i := 0; i < len(vulnStore); i++ {
		// ignore empty records (those records will be empty because they were grouped on previous iterations)
		if vulnStore[i] == nil {
			continue
		}

		// create a new vulnerabilty to group other similar vulnerabilities
		vGroup := &vulcan.Vulnerability{}

		// Add the current vulnerability to this group
		vGroup.Vulnerability.Vulnerabilities = append(vGroup.Vulnerability.Vulnerabilities, vulnStore[i].Vulnerability)

		// Break the Summary into separated words
		// ex.: PHP Multiple Vulnerabilities ---> [PHP, Multiple, Vulnerabilities]
		words1 := strings.Split(strings.ToLower(vulnStore[i].Vulnerability.Summary), " ")

		// Iterate over the remaining vulnerabilties
		for j := i + 1; j < len(vulnStore); j++ {
			// don't group if:
			// - vulnerabilities are not from the same asset
			// - vulnerabilities are not from vulcan-nessus
			if vulnStore[i] == nil ||
				vulnStore[j] == nil ||
				vulnStore[i].Asset != vulnStore[j].Asset ||
				!strings.Contains(vulnStore[i].CheckType, "nessus") ||
				!strings.Contains(vulnStore[j].CheckType, "nessus") {
				continue
			}

			// ignore empty records (those records will be empty because they were grouped on previous iterations)
			if vulnStore[j] != nil {

				// Break the Summary into separated words
				// ex.: PHP Multiple Vulnerabilities ---> [PHP, Multiple, Vulnerabilities]
				words2 := strings.Split(strings.ToLower(vulnStore[j].Vulnerability.Summary), " ")

				// we want to group vulnerabilities that have the same preffix
				if words1[0] == words2[0] {
					// ignore this entry if there are no recommendations
					if len(vulnStore[i].Vulnerability.Recommendations) == 0 ||
						len(vulnStore[j].Vulnerability.Recommendations) == 0 {
						continue
					}

					// get the summary similarity
					summarySimilarity := simhash.GetLikenessValue(
						vulnStore[i].Vulnerability.Summary,
						vulnStore[j].Vulnerability.Summary)

					// get the recommendations similarity
					recommendationsSimilarity := simhash.GetLikenessValue(
						vulnStore[i].Vulnerability.Recommendations[0],
						vulnStore[j].Vulnerability.Recommendations[0])

					// If Summary similarity is greater than 0.8 the vulnerabilties are grouped
					// If the sum of Summary similarity and Recommendation similarity is greater than 1.4 then the vulnerabilties are grouped
					// Vulnerabilities which have Recommendation too short will not be grouped
					if (summarySimilarity > 0.8 || summarySimilarity+recommendationsSimilarity >= 1.4) &&
						len(vulnStore[i].Vulnerability.Recommendations[0]) > 6 &&
						len(vulnStore[j].Vulnerability.Recommendations[0]) > 6 {
						// append vulnStore[j] to the current group
						vGroup.Vulnerability.Vulnerabilities = append(vGroup.Vulnerability.Vulnerabilities, vulnStore[j].Vulnerability)

						// empty vulnStore[j]
						vulnStore[j] = nil
					}
				}
			}
		}

		// if there are grouped vulnerabilities,
		// rewrite the Summary
		// rewirte the Description
		// and set it's vulnerabilties to be the same as the group
		if len(vGroup.Vulnerability.Vulnerabilities) > 1 {
			// Grab the "max" recommendation
			// This way, if we have multiples entries like
			// ---
			// PHP 5.3.x < 5.3.29 Multiple Vulnerabilities
			// PHP 5.3.x < 5.3.27 Multiple Vulnerabilities
			// PHP 5.3.x < 5.3.26 Multiple Vulnerabilities
			// ---
			// we can point the user to update to the last PHP version
			maxReco := ""
			for _, vuln := range vGroup.Vulnerability.Vulnerabilities {
				for _, recom := range vuln.Recommendations {
					if recom > maxReco {
						maxReco = recom
					}
				}
			}

			vulnStore[i].Vulnerability.Summary = vulnStore[i].Vulnerability.Summary + " And Similar"
			// Show the recommendation instead the description (because it is a group)
			vulnStore[i].Vulnerability.Description = maxReco
			vulnStore[i].Vulnerability.Vulnerabilities = vGroup.Vulnerability.Vulnerabilities
		}

	}

	// replace the original array of Vulnerabilities by the new groupe one
	reportData.Vulnerabilities = []vulcan.Vulnerability{}
	for i := 0; i < len(vulnStore); i++ {
		if vulnStore[i] == nil {
			continue
		}
		reportData.Vulnerabilities = append(reportData.Vulnerabilities, *vulnStore[i])
	}
	return reportData
}
© 2022 GitHub, Inc.
Terms
Privacy
Security
Status
Docs
Contact GitHub
Pricing
API
Training
Blog
About
Loading complete
