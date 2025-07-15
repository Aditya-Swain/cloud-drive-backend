from django.urls import path
from .views import GoogleRedirect,CreateFolder,DropboxCreateFolderView,CreateFolderView,OneDriveCallbackView,OneDriveLoginView,OneDriveStorageView,TaskCreationView,TaskDeleteView,DeleteCloudAccount,CloudFileTransferView,CloudFileDirectTransferView,DropboxOperations,GoogleCallback,DriveFiles,FileDeleteView,GooglePhotosDelete,GooglePhotosTransfer,FileTransferView,GoogleDriveDirectTransfer,GoogleDriveStorage,GooglePhotos,AddGoogleDrive, file_upload,google_callback_cloud,CombinedStorageView,DropboxCallback, AddDropbox, upload_folder


urlpatterns = [
   
    path("api/google/login/", GoogleRedirect.as_view(), name="google-login"),
    path("api/google/callback/", GoogleCallback.as_view(), name="google-callback"),
    path('api/drive/storage/', GoogleDriveStorage.as_view(), name='drive-storage'),
    path('api/google/add_cloud/', AddGoogleDrive.as_view(), name='add_google_cloud'),
    path('api/google/callback/cloud/', google_callback_cloud.as_view(), name='google_callback_cloud'),
    path('api/drive/all-storage/', CombinedStorageView.as_view(), name='drive-all-storage'),
    path("api/drive/files/<int:account_id>/", DriveFiles.as_view(), name="drive-files"),
    path("api/photos/<int:account_id>/", GooglePhotos.as_view(), name="google-photos"),
    path('api/drive/transfer/<str:action>/',TaskCreationView.as_view(), name='dropbox_operations'),
    path('api/drive/cut-paste/<str:action>/',TaskCreationView.as_view(), name='cut-paste-file'),
    path('api/dropbox/delete/',  TaskDeleteView.as_view(), name='delete-file'),
    path('api/drive/delete-files/', TaskDeleteView.as_view(), name='delete-files'),
    path('api/photos/transfer/', GooglePhotosTransfer.as_view(), name='google_photos_transfer'),
    path('api/photos/delete-files/', GooglePhotosDelete.as_view(), name='google_photos_delete'),
    path('api/dropbox/add_cloud/', AddDropbox.as_view(), name='add_dropbox_cloud'),
    path('api/dropbox/callback/', DropboxCallback.as_view(), name='dropbox_callback'),
    path('api/cloud/delete/<int:account_id>/',DeleteCloudAccount.as_view(), name='delete-cloud-account'),
    path('api/onedrive/login/', OneDriveLoginView.as_view(), name='onedrive_login'),
    path('api/onedrive/callback/', OneDriveCallbackView.as_view(), name='onedrive_callback'),
    path('api/onedrive/storage/', OneDriveStorageView.as_view(), name='onedrive_storage'),
    path('api/drive/accounts/<int:account_id>/create-folder/', CreateFolder.as_view(), name='create_new_folder'),
    path("api/file-upload/<str:account_id>/", file_upload, name="file_upload"),
    path("api/upload-folder/<str:account_id>/", upload_folder, name="upload_folder"),

    
]
    








