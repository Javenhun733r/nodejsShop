const fs = require('fs');

const deleteFile = filePath => {
	if (!filePath || filePath === 'undefined') {
		return;
	}
	fs.unlink(filePath, err => {
		if (err) {
			console.log(err);
		}
	});
};

exports.deleteFile = deleteFile;
