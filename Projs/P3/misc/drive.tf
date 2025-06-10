provider "google" {
  project = "csi-es"
  region  = "europe-west1"
}

resource "google_project_service" "drive" {
  project = "csi-es"
  service = "drive.googleapis.com"
}
