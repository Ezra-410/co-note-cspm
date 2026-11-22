mod "conote_cspm" {
  title       = "Co-note CSPM"
  description = "Cloud Security Posture dashboard for the Co-note AWS environment (CYB 319 - Lab 03)."
  categories  = ["aws", "security", "cspm"]
  require {
    mod "github.com/turbot/steampipe-mod-aws-compliance" {
      version = "*"
    }
  }
}