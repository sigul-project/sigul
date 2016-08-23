/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use, modify,
 * copy, or redistribute it subject to the terms and conditions of the GNU
 * General Public License v.2.  This program is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
 * implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.  You should have
 * received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
 * incorporated in the source code or documentation are not subject to the GNU
 * General Public License and may only be used or replicated with the express
 * permission of Red Hat, Inc.
 *
 * Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ostree.h>
#include <errno.h>


char *get_commit_data(char *directory, char *rev)
{
	GError *error = NULL;
	GVariant *commit_variant = NULL;
	GFile *path = g_file_new_for_path(directory);
	OstreeRepo *repo = ostree_repo_new(path);
	if(!ostree_repo_open(repo, NULL, &error)) {
		fprintf(stderr, "Failed to open repository: %s", error->message);
		return NULL;
	}
	if(!ostree_repo_load_variant(repo, OSTREE_OBJECT_TYPE_COMMIT, rev, &commit_variant, &error)) {
		fprintf(stderr, "Failed to load commit: %s", error->message);
		return NULL;
	}
	g_autoptr(GBytes) commit_data = g_variant_get_data_as_bytes(commit_variant);
	return g_base64_encode(g_bytes_get_data(commit_data, NULL),
			       g_bytes_get_size(commit_data));
}

bool import_signature(char *directory, char *rev, char *signature_line)
{
	GError *error = NULL;
	GFile *path = g_file_new_for_path(directory);
	OstreeRepo *repo = ostree_repo_new(path);
	gsize sig_len;
	guchar *sig_text = g_base64_decode(signature_line, &sig_len);
	GBytes *signature = g_bytes_new_take(sig_text, sig_len);
	if(!ostree_repo_open(repo, NULL, &error)) {
		fprintf(stderr, "Failed to open repository: %s\n", error->message);
		return false;
	}
	if(!ostree_repo_append_gpg_signature(repo, rev, signature, NULL, &error)) {
		fprintf(stderr, "Failed to attach signature: %s\n", error->message);
		return false;
	}
	return true;
}

bool init_repo(char *directory) {
	GError *error = NULL;
	GFile *path = g_file_new_for_path(directory);
	OstreeRepo *repo = ostree_repo_new(path);
	if(!ostree_repo_create(repo, OSTREE_REPO_MODE_ARCHIVE_Z2, NULL, &error)) {
		fprintf(stderr, "Failed to create repo: %s\n", error->message);
		return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	if(argc < 2) {
		fprintf(stderr, "No operation provided\n");
		return 1;
	}
	else if(strcmp(argv[1], "get-data") == 0) {
		if(argc != 4) {
			fprintf(stderr, "No directory or rev provided\n");
			return 1;
		}
		char *result = get_commit_data(argv[2], argv[3]);
		if(result == NULL)
			return 1;
		printf("%s\n", result);
		return 0;
	} else if(strcmp(argv[1], "import-signature") == 0) {
		if(argc != 4) {
			fprintf(stderr, "No directory or rev provided\n");
			return 1;
		}
		char *signature_input = NULL;
		size_t len;
		if(getline(&signature_input, &len, stdin) == -1) {
			fprintf(stderr, "Something went wrong: %s\n", strerror(errno));
			return 1;
		}
		if(!import_signature(argv[2], argv[3], signature_input)) {
			return 1;
		}
		return 0;
	} else if(strcmp(argv[1], "init-repo") == 0) {
		if(argc != 3) {
			fprintf(stderr, "No directory provided\n");
			return 1;
		}
		if(!init_repo(argv[2])) {
			return 1;
		}
		return 0;
	} else {
		fprintf(stderr, "Invalid operation: %s\n", argv[1]);
		return 1;
	}
}
