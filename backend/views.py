from venv import logger
from django.views import View
import time
import jwt,datetime,requests,uuid,urllib,json,dropbox
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from .models import UserProfile,CloudDriveConnection




class GoogleRedirect(APIView):
    def get(self, request):
        # Construct Google OAuth URL
        google_auth_url = (
               "https://accounts.google.com/o/oauth2/v2/auth"
                f"?client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}"
                "&response_type=code"
                f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
                "&scope=email%20profile%20https://www.googleapis.com/auth/drive%20https://www.googleapis.com/auth/photoslibrary.readonly"
                "&access_type=offline"
                "&prompt=consent"
                "&state=login"                             
                          )

        return redirect(google_auth_url)

class GoogleCallback(APIView):
    def get(self, request):
        # Retrieve the authorization code from the URL parameters
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Authorization code missing"}, status=status.HTTP_400_BAD_REQUEST)

        # Exchange the authorization code for access and refresh tokens
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            "client_secret": settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_response = requests.post(token_url, data=token_data)
        tokens = token_response.json()

        if "error" in tokens:
            return Response({"error": tokens["error"]}, status=status.HTTP_400_BAD_REQUEST)

        # Extract the tokens
        id_token_jwt = tokens.get("id_token")
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")  # Get refresh_token

        try:
            # Verify the ID token
            idinfo = id_token.verify_oauth2_token(id_token_jwt, Request(), settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY)

            # Extract user information
            email = idinfo.get("email")
            name = idinfo.get("name")

            # Check or create the user
            user, created = get_user_model().objects.get_or_create(email=email, defaults={"username": email, "first_name": name})

            # Create or update the UserProfile with the refresh_token
            user_profile, _ = UserProfile.objects.get_or_create(user=user)
            if refresh_token:
                print("Refresh Token:", tokens['refresh_token'])  # Save refresh_token only if it exists
                user_profile.refresh_token = refresh_token
                user_profile.save()

            # Generate a JWT token for the user
            jti = str(uuid.uuid4())
            payload = {
                "user_id": user.id,
                "email": user.email,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
                "iat": datetime.datetime.utcnow(),
                "jti": jti,
                "token_type": "access",
            }
            jwt_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

            # Redirect to frontend with JWT token
            frontend_url = f"{settings.FRONTEND_URL}/home?token={jwt_token}"
            return redirect(frontend_url)

        except ValueError as e:
            # Handle ID token verification errors
            return Response({"error": f"Invalid ID token: {e}"}, status=status.HTTP_400_BAD_REQUEST)


class GoogleDriveStorage(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_drive_service(self, user):
        """Authenticate and return the Google Drive API service."""
        SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
        
        # Correct access to user profile
        refresh_token = user.profile.refresh_token  # Access the refresh_token via user.profile
        
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )
        
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        
        service = build('drive', 'v3', credentials=creds)
        return service
    
    def get(self, request):
        """Handle GET request to return Google Drive storage details."""
        try:
            user = request.user  # Get authenticated user from request
            service = self.get_google_drive_service(user)
            
            # Call the Google Drive API to get storage information
            about = service.about().get(fields="storageQuota").execute()
            
            storage_quota = about.get('storageQuota', {})
            total_storage = storage_quota.get('limit', 0)
            used_storage = storage_quota.get('usage', 0)

            return Response({
                'total': total_storage,
                'used': used_storage
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": f"Failed to fetch storage data: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleDriveFiles(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_drive_service(self, connection):
        """Authenticate and return the Google Drive API service."""
        SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

        creds = Credentials(
            token=connection.access_token,
            refresh_token=connection.refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )
        
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build('drive', 'v3', credentials=creds)
        return service

    def get(self, request, account_id):
        """Handle GET request to return Google Drive files for a specific account and folder."""
        folder_id = request.query_params.get('folderId', 'root')  # Default to root folder if folderId is not provided
        try:
            # Get the user's specific connected Google Drive account
            connection = CloudDriveConnection.objects.get(id=account_id, user=request.user)
            service = self.get_google_drive_service(connection)

            # Query files and folders in the specified location (folderId)
            results = service.files().list(
                q=f"'{folder_id}' in parents and trashed=false",  # Filter by folderId (parents) and exclude trashed files
                pageSize=100,  # Number of files to retrieve (can be adjusted)
                fields="files(id, name, mimeType, size, createdTime, modifiedTime)"
            ).execute()

            files = results.get('files', [])

            # Prepare the response with file data
            file_data = []
            for file in files:
                # Add file or folder details
                item = {
                    "id": file.get("id"),
                    "name": file.get("name"),
                    "mimeType": file.get("mimeType"),
                    "size": file.get("size"),  # File size (only for files)
                    "createdTime": file.get("createdTime"),
                    "modifiedTime": file.get("modifiedTime"),
                }
                file_data.append(item)

            return Response({
                'files': file_data
            }, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Drive account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Failed to fetch drive files: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GooglePhotos(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_photos_service(self, connection):
        """Authenticate and return the Google Photos API service."""
        SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']

        creds = Credentials(
            token=connection.access_token,
            refresh_token=connection.refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build(
            'photoslibrary',
            'v1',
            credentials=creds,
            discoveryServiceUrl='https://photoslibrary.googleapis.com/$discovery/rest?version=v1'
        )
        return service

    def get(self, request, account_id):
        """Handle GET request to return Google Photos for a specific account."""
        try:
            # Fetch the connection for the given account_id
            connection = CloudDriveConnection.objects.get(id=account_id, user=request.user)
            service = self.get_google_photos_service(connection)

            all_photos = []
            next_page_token = None

            while True:
                # Call the Google Photos API to list media items
                results = service.mediaItems().list(
                    pageSize=100,
                    pageToken=next_page_token
                ).execute()

                media_items = results.get('mediaItems', [])
                next_page_token = results.get('nextPageToken', None)

                if media_items:
                    all_photos.extend(media_items)

                if not next_page_token:
                    break

            return Response({
                'photos': all_photos
            }, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Google Photos account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Failed to fetch Google Photos: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddGoogleDrive(APIView):
    def get(self, request):
        # Initiate the OAuth flow with Google
        google_oauth_url = "https://accounts.google.com/o/oauth2/auth"
        client_id = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
        redirect_uri = f"{settings.DJANGO_URL}/api/google/callback/cloud/"
        scope = "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/userinfo.email"
        response_type = "code"
        access_type = "offline"

        # Use the JWT token in the state parameter (if needed)
        token = str(AccessToken.for_user(request.user))  # Create a JWT for the user
        state = json.dumps({"jwt": token})  # Store the JWT in the state parameter

        # Construct the authorization URL
        auth_url = (
    f"{google_oauth_url}?client_id={client_id}&"
    f"redirect_uri={redirect_uri}&"
    f"scope={scope}&"
    f"response_type={response_type}&"
    f"access_type={access_type}&"
    f"prompt=consent&"
    f"state={urllib.parse.quote(state)}"
)

        return redirect(auth_url)

class google_callback_cloud(APIView):
    
    def get(self, request):
        # Extract the state from the URL params
        state = request.GET.get("state")
        if not state:
            return Response({"error": "State parameter missing"}, status=400)

        try:
            # Decode the state and extract the JWT token
            state_data = json.loads(state)
            token = state_data.get("jwt")
        except json.JSONDecodeError:
            return Response({"error": "Invalid state parameter"}, status=400)

        if not token:
            return Response({"error": "Authentication token missing"}, status=401)

        # Validate the JWT token
        try:
            access_token = AccessToken(token)  # Extract token from state
            user_id = access_token["user_id"]
            user = User.objects.get(id=user_id)
            request.user = user  # Set the authenticated user
        except Exception as e:
            return Response({"error": "Invalid token"}, status=401)

        # Get the authorization code from Google
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Authorization code missing"}, status=400)
        
        # Exchange the code for access tokens
        tokens = exchange_code_for_tokens(code)
        
        if 'access_token' not in tokens:
            return Response({"error": "Access token missing in the response from Google"}, status=400)

        access_token = tokens['access_token']
        
        # Call the method to get the Gmail email using the access token
        gmail_email = self.get_gmail_email_from_token(access_token)
        expiry_timestamp = int(time.time() * 1000)
        if gmail_email:
            # Save the connection in the database or return the email
            connection = CloudDriveConnection.objects.create(
                user=request.user,
                email=gmail_email,
                access_token=access_token,
                refresh_token=tokens.get('refresh_token', ''),
                provider='google_drive',
                expiry_time=expiry_timestamp,
            )
            # Redirect to the home page
            frontend_url=f"{settings.FRONTEND_URL}/home"
            return redirect(frontend_url)
    
        return Response({"error": "Failed to retrieve Gmail email address"}, status=400)


    def get_gmail_email_from_token(self, access_token):
        """
        Use the access token to fetch the user's Gmail email address.
        """
        url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(url, headers=headers)
        
        # Log the response for debugging
        if response.status_code != 200:
            # Log the response content to help debug
            print("Error response from Google API:", response.json())
            return None
        
        user_info = response.json()
        return user_info.get("email")    
def exchange_code_for_tokens(code):
    token_url = "https://oauth2.googleapis.com/token"
    client_id = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY  # From your settings
    client_secret = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET  # From your settings
    redirect_uri = f"{settings.DJANGO_URL}/api/google/callback/cloud/"  # Same as in AddGoogleDrive

    # Request payload
    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    # Send the POST request to Google
    response = requests.post(token_url, data=payload)

    if response.status_code == 200:
        # Parse and return the tokens
        tokens = response.json()
        return tokens
    else:
        # Handle errors
        return {
            "error": "Failed to exchange code for tokens",
            "details": response.json(),
        }


class GoogleDriveAllStorage(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_drive_service(self, refresh_token):
        """Authenticate and return the Google Drive API service."""
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build('drive', 'v3', credentials=creds)
        return service

    def get(self, request):
        """Fetch storage details for all connected Google Drive accounts."""
        try:
            user = request.user
            connected_accounts = CloudDriveConnection.objects.filter(user=user, provider='google_drive')
            storage_data = []


            for account in connected_accounts:
                try:
                    print(f"Processing Google Drive account: {account.email}")

                    service = self.get_google_drive_service(account.refresh_token)
                    about = service.about().get(fields="storageQuota").execute()

                    storage_quota = about.get('storageQuota', {})
                    total_storage = storage_quota.get('limit', 0)
                    used_storage = storage_quota.get('usage', 0)

                    storage_data.append({
                        "account_id": account.id,
                        "account_name": account.email,
                        "total": total_storage,
                        "used": used_storage
                    })

                    print(f"✅ Fetched storage for {account.email}")
                except Exception as e:
                    print(f"❌ Failed for {account.email}: {e}")

            return Response({"accounts": storage_data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"Failed to fetch storage data: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class GoogleDriveDirectTransfer(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_drive_service(self, refresh_token):
        """Authenticate and return the Google Drive API service."""
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        return build('drive', 'v3', credentials=creds)

    def post(self, request):
        """Transfer files from one Google Drive account to another and delete from source."""
        source_account_id = request.data.get('sourceAccountId')
        target_account_id = request.data.get('destinationAccountId')
        file_ids = request.data.get('fileIds')

        if not all([source_account_id, target_account_id, file_ids]):
            return Response({"error": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            source_account = CloudDriveConnection.objects.get(id=source_account_id, user=request.user)
            target_account = CloudDriveConnection.objects.get(id=target_account_id, user=request.user)

            source_service = self.get_google_drive_service(source_account.refresh_token)
            target_service = self.get_google_drive_service(target_account.refresh_token)

            transfer_status = []

            for file_id in file_ids:
                try:
                    # Step 1: Get original file metadata
                    file_metadata = source_service.files().get(fileId=file_id, fields="name").execute()
                    original_file_name = file_metadata.get("name")

                    # Step 2: Generate unique name for the destination
                    def get_unique_name(name):
                        existing_files = target_service.files().list(
                            q=f"name='{name}' and trashed=false",
                            fields="files(name)"
                        ).execute().get('files', [])
                        existing_names = [file['name'] for file in existing_files]
                        unique_name = name
                        while unique_name in existing_names:
                            unique_name = f"{unique_name}_copy"
                        return unique_name

                    unique_file_name = get_unique_name(original_file_name)

                    # Step 3: Share with target account
                    permission_body = {
                        "type": "user",
                        "role": "writer",
                        "emailAddress": target_account.email,
                    }
                    permission_response = source_service.permissions().create(
                        fileId=file_id,
                        body=permission_body,
                        fields="id"
                    ).execute()

                    # Step 4: Copy to target account
                    # Step 4: Copy the file to the target account
                    destination_folder_id = request.data.get('destinationPath') 
                    if destination_folder_id == '/':
                        destination_folder_id = None
                    print('path for cut',destination_folder_id) # ID of the target folder in the destination account
                    file_metadata_for_copy = {
                        "name": unique_file_name,
                        "parents": [destination_folder_id]  # Specify the target folder
                    }
                    copied_file = target_service.files().copy(fileId=file_id, body=file_metadata_for_copy).execute()


                    # Step 5: Remove sharing permission
                    source_service.permissions().delete(
                        fileId=file_id,
                        permissionId=permission_response["id"]
                    ).execute()

                    # Step 6: Delete the original file from source account
                    source_service.files().delete(fileId=file_id).execute()

                    transfer_status.append({
                        "file_id": file_id,
                        "status": "Transferred and deleted successfully",
                        "new_file_id": copied_file.get('id')
                    })

                except HttpError as file_error:
                    transfer_status.append({
                        "file_id": file_id,
                        "status": f"Error: {str(file_error)}",
                        "new_file_id": None
                    })

            return Response({"status": transfer_status}, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)
        except HttpError as e:
            return Response({"error": f"Google API error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class FileTransferView(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_drive_service(self, refresh_token):
        """Authenticate and return the Google Drive API service."""
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        return build('drive', 'v3', credentials=creds)

    def get_unique_name(self, target_service, name):
        """
        Generate a unique file name by appending '_copy' if necessary,
        considering only non-trashed and actively available files.
        """
        # Query only non-trashed files with the exact name
        query = f"name='{name}' and trashed=false"
        response = target_service.files().list(q=query, fields="files(id, name, trashed)").execute()
    
        existing_files = response.get('files', [])
        print(f"Querying for name='{name}': Found {len(existing_files)} files.")
        
        # Log existing files to debug if necessary
        for file in existing_files:
            print(f"File: {file['name']}, ID: {file['id']}, Trashed: {file['trashed']}")

        existing_names = [file['name'] for file in existing_files]
        # Generate a unique name if necessary
        unique_name = name
        while unique_name in existing_names:
            unique_name = f"{unique_name}_copy"
        
        return unique_name


    def post(self, request):
        """Directly transfer files from one Google Drive account to another."""
        source_account_id = request.data.get('sourceAccountId')  # Source account ID
        target_account_id = request.data.get('destinationAccountId')  # Target account ID
        file_ids = request.data.get('fileIds')  # List of file IDs to transfer

        if not all([source_account_id, target_account_id, file_ids]):
            return Response({"error": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            source_account = CloudDriveConnection.objects.get(id=source_account_id, user=request.user)
            target_account = CloudDriveConnection.objects.get(id=target_account_id, user=request.user)

            # Authenticate both accounts
            source_service = self.get_google_drive_service(source_account.refresh_token)
            target_service = self.get_google_drive_service(target_account.refresh_token)

            results = []  # To store transfer results for each file

            for file_id in file_ids:
                try:
                    # Step 1: Retrieve the original file name
                    file_metadata = source_service.files().get(fileId=file_id, fields="name").execute()
                    original_file_name = file_metadata.get("name")

                    # Step 2: Generate a unique file name for the copy
                    unique_file_name = self.get_unique_name(target_service, original_file_name)

                    # Step 3: Share the file with the target account
                    permission_body = {
                        "type": "user",
                        "role": "writer",
                        "emailAddress": target_account.email,
                    }
                    source_service.permissions().create(
                        fileId=file_id, body=permission_body, fields="id"
                    ).execute()

                    # Step 4: Copy the file to the target account
                    destination_folder_id = request.data.get('destinationPath')
                    if destination_folder_id == '/':
                        destination_folder_id = None
                    print('copy',destination_folder_id)
                    file_metadata_for_copy = {
                        "name": unique_file_name,
                        "parents": [destination_folder_id]  # Specify the target folder
                    }
                    copied_file = target_service.files().copy(fileId=file_id, body=file_metadata_for_copy).execute()

                    results.append({
                        "fileId": file_id,
                        "copiedFileId": copied_file.get('id'),
                        "status": "success",
                    })

                except HttpError as e:
                    results.append({
                        "fileId": file_id,
                        "status": "error",
                        "message": f"Google API error: {str(e)}",
                    })
                except Exception as e:
                    results.append({
                        "fileId": file_id,
                        "status": "error",
                        "message": f"Unexpected error: {str(e)}",
                    })

            return Response({"results": results}, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)
        except HttpError as e:
            return Response({"error": f"Google API error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_drive_service(self, refresh_token):
        """Authenticate and return the Google Drive API service."""
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        return build('drive', 'v3', credentials=creds)

    def delete(self, request):
        """Delete files from a Google Drive account."""
        # Parse request data
        source_account_id = request.data.get('sourceAccountId')
        file_ids = request.data.get('fileIds')

        # Validate required parameters
        if not source_account_id or not file_ids:
            return Response({"error": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the source account
            source_account = CloudDriveConnection.objects.get(id=source_account_id, user=request.user)

            # Authenticate the source Google Drive account
            source_service = self.get_google_drive_service(source_account.refresh_token)

            # Loop through and delete each file
            for file_id in file_ids:
                # Directly delete the file without moving it to trash
                source_service.files().delete(fileId=file_id).execute()

            return Response({"message": "Files deleted successfully."}, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Source account not found."}, status=status.HTTP_404_NOT_FOUND)
        except HttpError as e:
            return Response({"error": f"Google API error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Unexpected error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GooglePhotosTransfer(APIView):
    permission_classes = [IsAuthenticated]

    def get_google_photos_service(self, connection):
        """Authenticate and return the Google Photos API service."""
        SCOPES = ['https://www.googleapis.com/auth/photoslibrary']

        creds = Credentials(
            token=connection.access_token,
            refresh_token=connection.refresh_token,
            client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            token_uri="https://oauth2.googleapis.com/token"
        )

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build(
            'photoslibrary',
            'v1',
            credentials=creds,
            discoveryServiceUrl='https://photoslibrary.googleapis.com/$discovery/rest?version=v1'
        )
        return service
    def post(self, request):
        try:
            action = request.data.get('action')
            file_ids = request.data.get('fileIds', [])
            base_urls = request.data.get('baseUrls', [])
            source_account_id = request.data.get('sourceAccountId')
            destination_account_id = request.data.get('destinationAccountId')

            # Validate input
            print("Request Data:", action, file_ids, base_urls, source_account_id, destination_account_id)

             # Validate input
            if not action or not file_ids or not source_account_id or not destination_account_id:
                return Response({"error": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

        # If action is 'copy', validate baseUrls as well
            if action == 'copy' and not base_urls:
                return Response({"error": "Missing baseUrls for copy action."}, status=status.HTTP_400_BAD_REQUEST)


            # Get source and destination connections
            source_connection = CloudDriveConnection.objects.get(id=source_account_id, user=request.user)
            destination_connection = CloudDriveConnection.objects.get(id=destination_account_id, user=request.user)

            # Logic for copying files
            if action == 'copy':
                uploaded_tokens = []
                for base_url, file_id in zip(base_urls, file_ids):
                    photo_data = requests.get(base_url + "=d").content

                    upload_url = "https://photoslibrary.googleapis.com/v1/uploads"
                    headers = {
                        'Authorization': f"Bearer {destination_connection.access_token}",
                        'Content-type': 'application/octet-stream',
                        'X-Goog-Upload-File-Name': f"{file_id}.jpg",
                        'X-Goog-Upload-Protocol': 'raw'
                    }
                    upload_token = requests.post(upload_url, headers=headers, data=photo_data).text
                    uploaded_tokens.append(upload_token)

                # Create new items in destination account
                destination_service = self.get_google_photos_service(destination_connection)
                batch_create_response = destination_service.mediaItems().batchCreate(
                    body={
                        'newMediaItems': [
                            {'simpleMediaItem': {'uploadToken': token}} for token in uploaded_tokens
                        ]
                    }
                ).execute()

                return Response({
                    "message": "Photos copied successfully.",
                    "details": batch_create_response
                }, status=status.HTTP_201_CREATED)

            # Logic for cutting files
            elif action == 'cut':
                # Create service object for the source account
                source_service = self.get_google_photos_service(source_connection)

                for file_id in file_ids:
                    try:
                        # Delete each file individually from the source account
                        response = source_service.mediaItems().delete(mediaItemId=file_id).execute()
                    except HttpError as e:
                        return Response({"error": f"Failed to delete file {file_id}: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                return Response({"message": "Photos moved successfully."}, status=status.HTTP_200_OK)

            else:
                return Response({"error": "Invalid action specified."}, status=status.HTTP_400_BAD_REQUEST)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Google Photos account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class GooglePhotosDelete(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        try:
            # Extract the file IDs and account ID from the request body
            file_ids = request.data.get('fileIds', [])
            source_account_id = request.data.get('sourceAccountId')

            if not file_ids or not source_account_id:
                return Response({"error": "Missing required parameters."}, status=status.HTTP_400_BAD_REQUEST)

            # Get the source account connection (assumes CloudDriveConnection model)
            source_connection = CloudDriveConnection.objects.get(id=source_account_id, user=request.user)

            # Get the Google Photos API service
            service = get_google_photos_service(source_connection.credentials)

            # Initialize a list to store failed deletions
            failed_deletions = []

            # Loop over file IDs and delete each one
            for file_id in file_ids:
                try:
                    # Attempt to delete the media item from Google Photos
                    service.mediaItems().delete(mediaItemId=file_id).execute()
                    print(f"Successfully deleted photo with ID {file_id}.")
                except Exception as e:
                    # If deletion fails, log the error and add it to the failed list
                    print(f"Error deleting photo with ID {file_id}: {str(e)}")
                    failed_deletions.append(file_id)

            # Return response based on the result
            if failed_deletions:
                return Response({
                    "error": f"Failed to delete some photos with IDs: {failed_deletions}"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "Photos deleted successfully."}, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Google Photos account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
def get_google_photos_service(credentials):
    """Get the Google Photos service using the provided credentials."""
    SCOPES = ['https://www.googleapis.com/auth/photoslibrary']
    if not credentials or credentials.expired:
        credentials.refresh(Request())
    service = build('photoslibrary', 'v1', credentials=credentials)
    return service



class AddDropbox(APIView):
    def get(self, request):
        client_id = settings.DROPBOX_APP_KEY
        redirect_uri = f"{settings.DJANGO_URL}/api/dropbox/callback/"
        state = json.dumps({"jwt": str(request.auth)})
        
        auth_url = (
            f"https://www.dropbox.com/oauth2/authorize?"
            f"client_id={client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"response_type=code&"
            f"state={state}&"
            f"token_access_type=offline"
        )
        return redirect(auth_url)


class DropboxCallback(APIView):
    def get(self, request):
        code = request.GET.get('code')
        state = request.GET.get('state')
        
        if not code or not state:
            return Response({"error": "Missing code or state"}, status=400)
        
        # Decode JWT Token
        state_data = json.loads(state)
        jwt_token = state_data.get('jwt')

        from rest_framework_simplejwt.tokens import AccessToken
        try:
            decoded_token = AccessToken(jwt_token)
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)
        except Exception as e:
            return Response({"error": "Invalid JWT token"}, status=401)
        
        # Exchange Code for Tokens
        token_url = "https://api.dropboxapi.com/oauth2/token"
        payload = {
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': f"{settings.DJANGO_URL}/api/dropbox/callback/",
            'client_id': settings.DROPBOX_APP_KEY,
            'client_secret': settings.DROPBOX_APP_SECRET
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(token_url, data=payload, headers=headers)
        tokens = response.json()

        if 'access_token' not in tokens:  # Log the exact error
            return Response({"error": "Failed to exchange code for tokens", "details": tokens}, status=400)
        
        access_token = tokens['access_token']
        refresh_token = tokens.get('refresh_token', '')

        # Fetch Dropbox Account Info
        account_info = requests.post(
            'https://api.dropboxapi.com/2/users/get_current_account',
            headers={'Authorization': f'Bearer {access_token}'}
        ).json()
        
        email = account_info.get('email')

        # Save the Connection
        CloudDriveConnection.objects.create(
            user=user,
            email=email,  # Map Dropbox email to email
            access_token=access_token,
            refresh_token=refresh_token,
            provider='dropbox',
        )


        return redirect(f"{settings.FRONTEND_URL}/home")

def refresh_dropbox_token(account, request):
    
    # Attempt to get a new access token using the refresh token
    refresh_url = "https://api.dropboxapi.com/oauth2/token"
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': account.refresh_token,
        'client_id': settings.DROPBOX_APP_KEY,
        'client_secret': settings.DROPBOX_APP_SECRET  # Replace with your app's client secret
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.post(refresh_url, data=data, headers=headers)
    if response.status_code == 200:
        new_data = response.json()
        new_access_token = new_data.get('access_token')
        new_refresh_token = new_data.get('refresh_token')

        # Update database with new tokens
        account.access_token = new_access_token

        # Only update the refresh token if it's different (Dropbox returns a new refresh token occasionally)
        if new_refresh_token:
            account.refresh_token = new_refresh_token
        
        account.save()

        # Store the new access token in the session (so it is used immediately for subsequent requests)
        request.session['dropbox_access_token'] = new_access_token

    else:
        print(f"Failed to refresh token for account {account.email}: {response.json()}")



class DropboxAllStorage(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Fetch storage details for all connected Dropbox accounts."""
        try:
            user = request.user
            connected_accounts = CloudDriveConnection.objects.filter(user=user, provider='dropbox')
            storage_data = []

            for account in connected_accounts:
                # Debugging: Access token
                # Retrieve the latest access token from session (updated after refresh)
                access_token = request.session.get('dropbox_access_token', account.access_token)
            

                # Make API request
                response = requests.post(
                    'https://api.dropboxapi.com/2/users/get_space_usage',
                    headers={'Authorization': f'Bearer {access_token}'}
                )

                # Debugging: API response
                

                if response.status_code == 401:  # Unauthorized
                    
                    try:
                        # Refresh token and store it in the session
                        refresh_dropbox_token(account, request)

                        # Retry API request with refreshed token
                        access_token = request.session.get('dropbox_access_token')  # Use the refreshed token
                        response = requests.post(
                            'https://api.dropboxapi.com/2/users/get_space_usage',
                            headers={'Authorization': f'Bearer {access_token}'}
                        )
                        
                    except Exception as e:
                        return Response(
                            {"error": f"Failed to refresh token for account {account.email}: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )

                if response.status_code != 200:
                    return Response(
                        {"error": f"Failed to fetch storage for {account.email}", "details": response.json()},
                        status=response.status_code
                    )

                space_data = response.json()
                total_storage = space_data.get('allocation', {}).get('allocated', 0)
                used_storage = space_data.get('used', 0)

                storage_data.append({
                    "account_id": account.id,
                    "account_name": account.email,
                    "total": total_storage,
                    "used": used_storage
                })

            return Response({"accounts": storage_data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to fetch Dropbox storage data: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CombinedStorageView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Invoke GoogleDriveAllStorage, DropboxAllStorage, and OneDriveStorageView and combine their responses."""
        try:
            # Call GoogleDriveAllStorage
            google_drive_view = GoogleDriveAllStorage.as_view()
            google_drive_response = google_drive_view(request._request).render()
            google_drive_data = google_drive_response.data

            # Call DropboxAllStorage
            dropbox_view = DropboxAllStorage.as_view()
            dropbox_response = dropbox_view(request._request).render()
            dropbox_data = dropbox_response.data

            # Call OneDriveStorageView
            onedrive_view = OneDriveStorageView.as_view()
            onedrive_response = onedrive_view(request._request).render()
            onedrive_data = onedrive_response.data

            # Combine responses
            combined_data = {
                "google_drive": google_drive_data.get('accounts', []),
                "dropbox": dropbox_data.get('accounts', []),
                "onedrive": onedrive_data.get('accounts', []),
            }

            print('all-storage---------------',combined_data)

            return Response(combined_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"Failed to fetch storage data: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DropboxFiles(APIView):
    permission_classes = [IsAuthenticated]

    def get_dropbox_client(self, connection):
        """Authenticate and return the Dropbox API client."""
        access_token = connection.access_token
        return dropbox.Dropbox(access_token)

    def get(self, request, account_id):
        """
        Handle GET request to return Dropbox files and folders for a specific account.
        Fetches root files and folders if no folderId is provided,
        otherwise fetches contents of the specified folder.
        """
        try:
            # Get the user's specific connected Dropbox account
            connection = CloudDriveConnection.objects.get(id=account_id, user=request.user, provider='dropbox')
            dbx = self.get_dropbox_client(connection)

            # Get the folderId (path) from query parameters, default to root ('') if not provided
            folder_path = request.query_params.get('folderId', '')

            # Call the Dropbox API to list files and folders in the specified folder
            result = dbx.files_list_folder(folder_path)
            entries = result.entries

            # Prepare the data for files and folders
            items = []
            for entry in entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    # It's a file, include file-specific metadata
                    items.append({
                        "type": "file",
                        "name": entry.name,
                        "path_display": entry.path_display,
                        "id": entry.id,
                        "size": entry.size,  # File size
                    })
                elif isinstance(entry, dropbox.files.FolderMetadata):
                    # It's a folder, include folder-specific metadata
                    items.append({
                        "type": "folder",
                        "name": entry.name,
                        "path_display": entry.path_display,
                        "id": entry.id,
                    })

            # Include folder path in the response for better navigation support
            return Response({
                'folder_path': folder_path,  # Current folder path
                'files': items              # Files and folders inside
            }, status=status.HTTP_200_OK)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Dropbox account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except dropbox.exceptions.ApiError as e:
            return Response({"error": f"Dropbox API error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Failed to fetch Dropbox files: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DriveFiles(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id):
        """Handle GET request to return files for a specific account based on the provider (Google Drive, Dropbox, or OneDrive)."""
        try:
            # Get the user's specific connected cloud drive account
            connection = CloudDriveConnection.objects.get(id=account_id, user=request.user)
            
            # Check the provider and call the appropriate class method
            if connection.provider == "google_drive":
                google_drive_view = GoogleDriveFiles()
                return google_drive_view.get(request, account_id)  # Call the GoogleDriveFiles.get method directly
            elif connection.provider == "dropbox":
                dropbox_view = DropboxFiles()
                return dropbox_view.get(request, account_id)  # Call the DropboxFiles.get method directly
            elif connection.provider == "onedrive":
                onedrive_view = OneDriveFilesView()
                return onedrive_view.get(request, account_id)  # Call OneDriveFilesView.get method directly
            else:
                return Response({"error": "Unsupported provider."}, status=status.HTTP_400_BAD_REQUEST)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Drive account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Failed to fetch drive files: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


import dropbox
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import CloudDriveConnection


class DropboxOperations(APIView):
    permission_classes = [IsAuthenticated]

    def get_dropbox_client(self, connection):
        """Authenticate and return the Dropbox client."""
        return dropbox.Dropbox(connection.access_token)

    def validate_paths(self, client, paths):
        """Validate the existence of paths in Dropbox."""
        missing_files = []
        for path in paths:
            try:
                metadata = client.files_get_metadata(path)
                print(f"Found source file: {metadata.path_display}")
            except dropbox.exceptions.ApiError as e:
                if isinstance(e.error, dropbox.files.LookupError):
                    missing_files.append(path)
                else:
                    print(f"API error occurred for path: {path} - {e}")
                    raise
        return missing_files

    def post(self, request):
        """Handle file operations on Dropbox."""
        try:
            source_account_id = request.data.get('sourceAccountId')
            destination_account_id = request.data.get('destinationAccountId')

            if not source_account_id:
                return Response({"error": "Source account ID is required."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                source_connection = CloudDriveConnection.objects.get(
                    id=source_account_id, user=request.user, provider='dropbox'
                )
                source_client = self.get_dropbox_client(source_connection)
            except CloudDriveConnection.DoesNotExist:
                return Response({"error": "Source Dropbox account not found."}, status=status.HTTP_404_NOT_FOUND)

            operation = request.data.get('action')
            from_paths = request.data.get('sourcePaths', [])

            if isinstance(from_paths, str):
                from_paths = [from_paths]

            if operation in ['copy', 'cut']:
                if not destination_account_id:
                    return Response({"error": "Destination account ID is required."}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    destination_connection = CloudDriveConnection.objects.get(
                        id=destination_account_id, user=request.user, provider='dropbox'
                    )
                    destination_client = self.get_dropbox_client(destination_connection)
                except CloudDriveConnection.DoesNotExist:
                    return Response({"error": "Destination Dropbox account not found."}, status=status.HTTP_404_NOT_FOUND)

                to_path = request.data.get('destinationPath', '/')

                for path in from_paths:
                    try:
                        # First download the file from source
                        _, response = source_client.files_download(path)
                        file_content = response.content

                        # Upload to destination
                        filename = path.split('/')[-1]
                        destination = f"{to_path.rstrip('/')}/{filename}"

                        destination_client.files_upload(
                            file_content,
                            destination,
                            mode=dropbox.files.WriteMode('overwrite')
                        )

                        if operation == 'cut':
                            # Delete from source after successful upload
                            source_client.files_delete_v2(path)

                    except dropbox.exceptions.ApiError as e:
                        operation_name = "move" if operation == "cut" else "copy"
                        return Response(
                            {"error": f"Failed to {operation_name} file {path}: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )

                success_message = "Files moved successfully." if operation == "cut" else "Files copied successfully."
                return Response({"message": success_message}, status=status.HTTP_200_OK)

            if operation == 'delete':
                if not from_paths:
                    return Response({"error": "Source paths are required."},
                                    status=status.HTTP_400_BAD_REQUEST)

                for path in from_paths:
                    if not path:
                        continue
                    try:
                        source_client.files_delete_v2(path)
                    except dropbox.exceptions.ApiError as e:
                        print(f"Delete error for path {path}: {str(e)}")
                        if isinstance(e.error, dropbox.files.DeleteError):
                            return Response(
                                {"error": f"Failed to delete file {path}: {str(e)}"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                        return Response(
                            {"error": f"Failed to delete file {path}: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )

                return Response({"message": "Files deleted successfully."},
                                status=status.HTTP_200_OK)


            else:
                return Response({"error": "Invalid operation type."},
                                status=status.HTTP_400_BAD_REQUEST)
        except dropbox.exceptions.AuthError as auth_error:
            return Response(
                {"error": "Authentication failed. Please reconnect your Dropbox account."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except dropbox.exceptions.ApiError as e:
            return Response({"error": f"Dropbox API error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import CloudDriveConnection

class CloudFileTransferView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Handle file operations on Dropbox or Google Drive."""
        try:
            source_account_id = request.data.get('sourceAccountId')
            destination_account_id = request.data.get('destinationAccountId')

            if not source_account_id:
                return Response({"error": "Source account ID is required."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                source_connection = CloudDriveConnection.objects.get(
                    id=source_account_id, user=request.user
                )
                # Check the provider and call the appropriate class method
                if source_connection.provider == 'google_drive':
                    google_drive_operations = FileTransferView()
                    return google_drive_operations.post(request)  # Call post method of GoogleDriveFiles
                elif source_connection.provider == 'dropbox':
                    dropbox_operations = DropboxOperations()
                    return dropbox_operations.post(request)  # Call post method of DropboxOperations
                else:
                    return Response({"error": "Unsupported provider."}, status=status.HTTP_400_BAD_REQUEST)

            except CloudDriveConnection.DoesNotExist:
                return Response({"error": "Source account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": f"Failed to transfer file: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class CloudFileDirectTransferView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Handle file operations on Dropbox or Google Drive."""
        try:
            source_account_id = request.data.get('sourceAccountId')

            if not source_account_id:
                return Response({"error": "Source account ID is required."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                source_connection = CloudDriveConnection.objects.get(
                    id=source_account_id, user=request.user
                )
                # Check the provider and call the appropriate class method
                if source_connection.provider == 'google_drive':
                    google_drive_operations = GoogleDriveDirectTransfer()
                    return google_drive_operations.post(request)  # Call post method of GoogleDriveFiles
                elif source_connection.provider == 'dropbox':
                    dropbox_operations = DropboxOperations()
                    return dropbox_operations.post(request)  # Call post method of DropboxOperations
                else:
                    return Response({"error": "Unsupported provider."}, status=status.HTTP_400_BAD_REQUEST)

            except CloudDriveConnection.DoesNotExist:
                return Response({"error": "Source account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": f"Failed to transfer file: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)        

class DeleteCloudAccount(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, account_id):
        try:
            # Get the cloud account associated with the user and the given account_id
            account = CloudDriveConnection.objects.filter(id=account_id, user=request.user).first()

            if not account:
                return Response(
                    {"error": "Account not found or you don't have permission to delete it."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Delete the account
            account.delete()
            return Response({"message": "Cloud account deleted successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


from django.http import HttpResponse, JsonResponse
from django.utils.timezone import now
from .models import CloudDriveConnection, Task  
from rest_framework.views import APIView
import json
from .utils import poll_task_completion, get_task_response  # Import both functions

class TaskCreationView(APIView):
    def post(self, request, action):
        try:
            # Parse the JSON body
            body = json.loads(request.body)
            file_ids = body.get("fileIds", [])
            base_urls = body.get("baseUrls", [])
            action = body.get("action", [])
            source_paths = body.get("sourcePaths", [])
            source_account_id = body.get("sourceAccountId")
            destination_account_id = body.get("destinationAccountId")
            destination_path = body.get("destinationPath", "/")

            # Validate required fields
            if not action or not source_account_id or not destination_account_id:
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Fetch source and destination account connections
            try:
                source_connection = CloudDriveConnection.objects.get(id=source_account_id)
                destination_connection = CloudDriveConnection.objects.get(id=destination_account_id)
            except CloudDriveConnection.DoesNotExist:
                return JsonResponse({"error": "Invalid source or destination account ID"}, status=404)

            # Get the emails for the source and destination
            source_email = source_connection.email
            destination_email = destination_connection.email

            # Create a task for each file
            tasks = []
            for index, source_path in enumerate(source_paths):
                # Handle GOOGLE_DRIVE specific case for source_path
                if source_connection.provider.upper() == "GOOGLE_DRIVE":
                    source_path = file_ids[index] if index < len(file_ids) else None

                task = Task.objects.create(
                    cloud_service=source_connection.provider.upper(),
                    source_account_id=source_account_id,
                    destination_account_id=destination_account_id,
                    source_path=source_path,
                    destination_path=f"{destination_path.rstrip('/')}/{base_urls[index]}" if base_urls else destination_path,
                    task_type=action.upper(),
                    source_email=source_email,
                    destination_email=destination_email,
                    user_id=source_connection.user.id,
                    status="PENDING",  # Use string constant instead of Task.PENDING
                    created_at=now(),
                )
                tasks.append(task.id)

            # Use the polling utility and response helper
            completed_tasks, failed_tasks, pending_tasks, status_code = poll_task_completion(tasks)
            return get_task_response(completed_tasks, failed_tasks, pending_tasks, status_code)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON body"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)


from django.http import JsonResponse
from django.utils.timezone import now
from .models import CloudDriveConnection, Task  
from rest_framework.views import APIView
import json
from .utils import poll_task_completion, get_task_response  # Import both utilities

class TaskDeleteView(APIView):
    def post(self, request):
        try:
            # Parse the JSON body
            body = json.loads(request.body)
            file_ids = body.get("fileIds", [])
            source_paths = body.get("sourcePaths", [])
            source_account_id = body.get("sourceAccountId")

            # Validate required fields
            if not source_account_id:
                return JsonResponse({"error": "Missing source account ID"}, status=400)

            # Fetch source connection
            try:
                source_connection = CloudDriveConnection.objects.get(id=source_account_id)
            except CloudDriveConnection.DoesNotExist:
                return JsonResponse({"error": "Invalid source account ID"}, status=404)

            # If the source provider is Dropbox, ensure sourcePaths are provided
            if source_connection.provider == 'dropbox' and not source_paths:
                return JsonResponse({"error": "Source paths are required for Dropbox deletion."}, status=400)

            # If the source provider is Google Drive, ensure fileIds are provided
            if source_connection.provider == 'google_drive' and not file_ids:
                return JsonResponse({"error": "File IDs are required for Google Drive deletion."}, status=400)

            # Create a task for each file to delete
            tasks = []
            if source_connection.provider == 'dropbox':
                # Create tasks for Dropbox (using sourcePaths)
                for source_path in source_paths:
                    task = Task.objects.create(
                        cloud_service=source_connection.provider.upper(),
                        source_account_id=source_account_id,
                        source_path=source_path,
                        destination_account_id=0,
                        source_email=source_connection.email,
                        destination_email="",
                        destination_path="",
                        task_type="DELETE",
                        user_id=source_connection.user.id,
                        status="PENDING",  # Use string constant instead of Task.PENDING
                        created_at=now(),
                    )
                    tasks.append(task.id)
            elif source_connection.provider == 'google_drive':
                # Create tasks for Google Drive (using fileIds)
                for file_id in file_ids:
                    task = Task.objects.create(
                        cloud_service=source_connection.provider.upper(),
                        source_account_id=source_account_id,
                        source_email=source_connection.email,
                        destination_email="",
                        destination_account_id=0,
                        source_path=file_id,
                        destination_path="",
                        task_type="DELETE",
                        user_id=source_connection.user.id,
                        status="PENDING",  # Use string constant instead of Task.PENDING
                        created_at=now(),
                    )
                    tasks.append(task.id)

            # Use the polling utility and response helper
            completed_tasks, failed_tasks, pending_tasks, status_code = poll_task_completion(tasks)
            return get_task_response(completed_tasks, failed_tasks, pending_tasks, status_code)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON body"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        
class OneDriveLogin(APIView):
    """Handles the OneDrive OAuth2 login redirection."""

    def get(self, request):
        """Redirect the user to OneDrive OAuth2 login."""
        auth_url = (
            f"{settings.ONEDRIVE_AUTH_URL}?"
            f"client_id={settings.ONEDRIVE_CLIENT_ID}"
            f"&response_type=code"
            f"&redirect_uri={settings.ONEDRIVE_REDIRECT_URI}"
            f"&scope=Files.ReadWrite offline_access"
        )
        return Response({"redirect_url": auth_url}, status=status.HTTP_302_FOUND)
        

class OneDriveLoginView(APIView):
    """Handles the OneDrive OAuth2 login redirection."""

    def get(self, request):
        """Redirect the user to OneDrive OAuth2 login."""
        auth_url = (
            f"{settings.ONEDRIVE_AUTH_URL}?"
            f"client_id={settings.ONEDRIVE_CLIENT_ID}"
            f"&response_type=code"
            f"&redirect_uri={settings.ONEDRIVE_REDIRECT_URI}"
            f"&scope=Files.ReadWrite offline_access"
        )
        return Response({"redirect_url": auth_url}, status=status.HTTP_302_FOUND)

class OneDriveCallbackView(APIView):
    def get(self, request):
        # Get the code and state from the request
        code = request.GET.get('code')
        state = request.GET.get('state')
        
        if not code or not state:
            return Response({"error": "Missing code or state"}, status=400)
        
        # Decode JWT Token from state
        try:
            state_data = json.loads(state)
            jwt_token = state_data.get('jwt')
            decoded_token = AccessToken(jwt_token)  # Decode and validate the token
            user_id = decoded_token['user_id']  # Extract the user ID
            user = User.objects.get(id=user_id)  # Fetch the user from the database
        except Exception as e:
            return Response({"error": "Invalid JWT token", "details": str(e)}, status=401)
        
        # Exchange the authorization code for OneDrive tokens
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        payload = {
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': f'{settings.SPRING_URL}/api/onedrive/callback/',
            'client_id': "",
            'client_secret':""
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        # Make the POST request to get the tokens
        response = requests.post(token_url, data=payload, headers=headers)
        tokens = response.json()

        if 'access_token' not in tokens:  # Log the error if access_token is missing
            return Response({"error": "Failed to exchange code for tokens", "details": tokens}, status=400)
        
        access_token = tokens['access_token']
        refresh_token = tokens.get('refresh_token', '')

        # Fetch OneDrive Account Info
        account_info = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {access_token}'}
        ).json()
        
        email = account_info.get('userPrincipalName')

        # Save the OneDrive connection in the database
        CloudDriveConnection.objects.create(
            user=user,
            email=email,  # Store OneDrive email
            access_token=access_token,
            refresh_token=refresh_token,
            provider='onedrive',
        )

        # Redirect to the frontend page after successful connection
        frontend_url = f"{settings.FRONTEND_URL}/home"
        return redirect(frontend_url)

class OneDriveStorageView(APIView):
    """Fetches OneDrive storage details for all connected OneDrive accounts."""

    def get(self, request):
        try:
            user = request.user
            connected_accounts = CloudDriveConnection.objects.filter(user=user, provider="onedrive")
            storage_data = []

            for account in connected_accounts:
                access_token = account.access_token  # Fetch stored access token
                headers = {"Authorization": f"Bearer {access_token}"}
                response = requests.get("https://graph.microsoft.com/v1.0/me/drive/quota", headers=headers)

                # If access token expired, refresh it
                if response.status_code == 401:
                    new_tokens = self.refresh_access_token(account.refresh_token)
                    if "access_token" in new_tokens:
                        # Update the stored tokens
                        account.access_token = new_tokens["access_token"]
                        account.refresh_token = new_tokens.get("refresh_token", account.refresh_token)
                        account.save()

                        # Retry fetching storage with the new token
                        headers = {"Authorization": f"Bearer {account.access_token}"}
                        response = requests.get("https://graph.microsoft.com/v1.0/me/drive/quota", headers=headers)

                        # If it still fails, return an error
                        if response.status_code != 200:
                            return Response(
                                {"error": f"Failed to fetch storage after refreshing token for {account.email}"},
                                status=response.status_code
                            )
                    else:
                        return Response(
                            {"error": f"Failed to refresh access token for {account.email}"},
                            status=status.HTTP_401_UNAUTHORIZED
                        )

                if response.status_code != 200:
                    print(f"Failed to fetch OneDrive storage for {account.email}. Response: {response.json()}")
                    return Response(
                        {"error": f"Failed to fetch storage for {account.email}", "details": response.json()},
                        status=response.status_code
                    )

                # Extract storage details
                quota_data = response.json()
                storage_data.append({
                    "account_id": account.id,
                    "account_name": account.email,
                    "total": quota_data.get("total", 0),
                    "used": quota_data.get("used", 0),
                    "remaining": quota_data.get("remaining", 0),
                    "state": quota_data.get("state", "unknown")
                })

            return Response({"accounts": storage_data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to fetch OneDrive storage data: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def refresh_access_token(self, refresh_token):
        """Refresh OneDrive Access Token using the Refresh Token"""


        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        payload = {
            'client_id': "",
            'client_secret': "",
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        response = requests.post(token_url, data=payload, headers=headers)
        tokens = response.json()

        if "access_token" in tokens:
            print("New access token obtained successfully.")
        else:
            print(f"Failed to refresh token. Response: {tokens}")

        return tokens


import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .models import CloudDriveConnection  # Adjust this import as needed

import requests
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .models import CloudDriveConnection
import requests

class OneDriveFilesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, account_id):
        print(f"Received account_id: {account_id}")
        """Fetch files from OneDrive for the selected account."""
        try:
            user = request.user

            # Fetch only the selected account
            try:
                connection = CloudDriveConnection.objects.get(id=account_id, user=user, provider="onedrive")
            except CloudDriveConnection.DoesNotExist:
                return Response({"error": "Invalid OneDrive account."}, status=status.HTTP_404_NOT_FOUND)

            # Retrieve access token
            access_token = request.session.get("onedrive_access_token", connection.access_token)

            # Get the folder path from the query parameters (default to root if not provided)
            folder_path = request.query_params.get("folderId", "")

            # Construct the URL to fetch the folder contents
            if folder_path:
                url = f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_path}/children"
            else:
                url = "https://graph.microsoft.com/v1.0/me/drive/root/children"  # Root folder

            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(url, headers=headers)

            if response.status_code == 401:
                return Response({"error": "Unauthorized. Token might be expired."}, status=status.HTTP_401_UNAUTHORIZED)

            if response.status_code != 200:
                return Response(
                    {"error": "Failed to fetch OneDrive files", "details": response.json()},
                    status=response.status_code,
                )

            # Extract file details
            files_data = response.json().get("value", [])
            files_list = [
                {
                    "name": file.get("name"),
                    "id": file.get("id"),
                    "size": file.get("size"),
                    "created_time": file.get("createdDateTime"),
                    "modified_time": file.get("lastModifiedDateTime"),
                    "type": "folder" if "folder" in file else "file",
                    "mimeType": file.get("file", {}).get("mimeType", "") if "file" in file else "folder",
                    "download_url": file.get("@microsoft.graph.downloadUrl", "") if "file" in file else None,
                }
                for file in files_data
            ]

            return Response({"files": files_list}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"Failed to fetch OneDrive files: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

import json
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from .models import CloudDriveConnection  # Import your model

SCOPES = ['https://www.googleapis.com/auth/drive']

import json
from django.http import JsonResponse
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from .models import CloudDriveConnection 
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import json
from django.http import JsonResponse
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .models import CloudDriveConnection

@method_decorator(csrf_exempt, name='dispatch') # Import your model
  # Assuming you have the helper function for getting the service

class CreateFolderView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def post(self, request, account_id):
        print(f"User: {request.user}, Authenticated: {request.user.is_authenticated}")
        
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Unauthorized"}, status=401)

        try:
            data = json.loads(request.body)
            folder_name = data.get('folder_name')
            new_folder_path = data.get('new_folder_path', '')

            if new_folder_path == '/':
                new_folder_path = 'root'

            if not folder_name:
                return JsonResponse({'error': 'Folder name is required'}, status=400)

            drive_connection = CloudDriveConnection.objects.filter(
                id=account_id, user=request.user, provider="google_drive"
            ).first()

            if not drive_connection:
                return JsonResponse({"error": "Account not found or permission denied."}, status=404)

            credentials = Credentials(
                token=drive_connection.access_token,
                refresh_token=drive_connection.refresh_token,
                client_id=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
                client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
                token_uri='https://oauth2.googleapis.com/token'
            )

            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())  # Refresh the token

                # Save the new access token and refresh token
                drive_connection.access_token = credentials.token
                drive_connection.refresh_token = credentials.refresh_token
                drive_connection.save()
            service = build("drive", "v3", credentials=credentials)

            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [new_folder_path] if new_folder_path != 'root' else ["root"]
            }

            folder = service.files().create(body=folder_metadata, fields='id').execute()

            return JsonResponse({'message': 'Folder created successfully', 'folder_id': folder.get('id')}, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

import json
import dropbox
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404
from .models import CloudDriveConnection

@method_decorator(csrf_exempt, name='dispatch')
class DropboxCreateFolderView(View):
    def post(self, request, account_id):
        try:
            # Parse request data
            data = json.loads(request.body)
            folder_name = data.get('folder_name', '').strip()
            new_folder_path = data.get('new_folder_path', '').strip()

            # Validate folder name
            if not folder_name:
                return JsonResponse({'status': 'error', 'message': 'Folder name cannot be empty'}, status=400)
            

            # Retrieve the Dropbox account details
            drive_connection = get_object_or_404(CloudDriveConnection, id=account_id)

            if drive_connection.provider != 'dropbox':
                return JsonResponse({'status': 'error', 'message': 'Invalid provider, expected Dropbox'}, status=400)

            # Initialize Dropbox client
            dbx = dropbox.Dropbox(drive_connection.access_token)

            # Ensure correct path formatting
            # Ensure correct path formatting
            if new_folder_path == "/":
                full_path = f"/{folder_name}"
            elif new_folder_path.endswith(f"/{folder_name}"):
                full_path = new_folder_path  # Prevents appending the same folder name
            else:
                full_path = f"{new_folder_path}/{folder_name}"


            # Check if the folder already exists
            try:
                dbx.files_get_metadata(full_path)
                return JsonResponse({'status': 'error', 'message': 'Folder already exists'}, status=400)
            except dropbox.exceptions.ApiError:
                # Folder does not exist, proceed with creation
                pass

            # Create the folder in Dropbox
            dbx.files_create_folder_v2(full_path)

            return JsonResponse({'status': 'success', 'message': 'Folder created successfully', 'folder_path': full_path}, status=201)

        except dropbox.exceptions.ApiError as e:
            return JsonResponse({'status': 'error', 'message': f"Dropbox API error: {e}"}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

class CreateFolder(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, account_id):
        """Handle GET request to return files for a specific account based on the provider (Google Drive, Dropbox, or OneDrive)."""
        try:
            # Get the user's specific connected cloud drive account
            connection = CloudDriveConnection.objects.get(id=account_id, user=request.user)
            
            # Check the provider and call the appropriate class method
            if connection.provider == "google_drive":
                google_drive_view = CreateFolderView()
                return google_drive_view.post(request, account_id)  # Call the GoogleDriveFiles.get method directly
            elif connection.provider == "dropbox":
                dropbox_view = DropboxCreateFolderView()
                return dropbox_view.post(request, account_id)  # Call the DropboxFiles.get method directly
            else:
                return Response({"error": "Unsupported provider."}, status=status.HTTP_400_BAD_REQUEST)

        except CloudDriveConnection.DoesNotExist:
            return Response({"error": "Drive account not found or unauthorized."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Failed to fetch drive files: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
def file_upload(request, account_id):
    if request.method == "POST":
        try:
            files = request.FILES.getlist('files')
            destination_path = request.POST.get('destination_path')
            account_type = request.POST.get('drive_type')
            print('file_upload python api called -------------------------')
            print('account type ::::',account_type)
            
            
            if not files:
                return JsonResponse({"error": "No files provided"}, status=400)
            
            # Create a new session for requests
            session = requests.Session()
            
            # Prepare the files data - note the key is now 'files' to match Java API
            files_data = []
            for file in files:
                files_data.append(('files', (file.name, file.read(), file.content_type)))
            
            # Add destination_path as form data
            data = {'destination_path': destination_path,'account_type':account_type}
            
            # Java API URL
            JAVA_API_URL = f"{settings.SPRING_URL}/api/upload-file/{account_id}"
            
            # Send request to Java API
            response = session.post(
                JAVA_API_URL,
                files=files_data,
                data=data
            )
            
            if response.status_code != 200:
                return JsonResponse({
                    "error": f"Java API returned status {response.status_code}: {response.text}"
                }, status=response.status_code)
            
            return JsonResponse(response.json())
            
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    
    return JsonResponse({"error": "Invalid request method"}, status=405)
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # Disable CSRF for testing (Not recommended for production)
def upload_folder(request, account_id):
    if request.method == "POST":
        try:
            files = request.FILES.getlist('folderFiles')  # Extracting folder files
            folder_name = request.POST.get('folder_name')  # Extracting folder name
            destination_path = request.POST.get('destination_path')  # Extracting destination path
            account_type = request.POST.get('drive_type')

            if not files:
                return JsonResponse({"error": "No files provided"}, status=400)

            # Prepare files for forwarding
            files_data = [
                ("folderFiles", (file.name, file, file.content_type)) for file in files
            ]

            # Java API URL where files will be sent
            JAVA_API_URL = f"{settings.SPRING_URL}/api/upload-folder/{account_id}"

            # Forwarding request to Java API
            response = requests.post(JAVA_API_URL, files=files_data, data={"folder_name": folder_name, "destination_path": destination_path,"account_type":account_type})

            # Sending response back to frontend
            return JsonResponse({"status": response.status_code, "message": response.text})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)
