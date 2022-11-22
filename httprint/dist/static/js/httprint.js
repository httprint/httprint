function uploadFile() {
    let photo = document.getElementById("upload-file").files[0];
    let copies = document.getElementById("copies").value;
    let formData = new FormData();

    formData.append("file", photo);
    formData.append("copies", copies);
    var uploadField = document.getElementById("upload-file");
    fetch("/api/upload", {method: "POST", body: formData})
        .then(function(response) {
            return response.json();
        })
        .then(function(reply) {
            if (reply && !reply.error) {
                $.toast({
                    text: reply.message || "file sent to printer",
                    heading: "DONE!",
                    icon: "success",
                    showHideTransition: "fade",
                    allowToastClose: true,
                    hideAfter: false,
                    stack: 5,
                    position: "top-center"
                });
                uploadField.value = null;
                copies.value = 1;
            } else {
                $.toast({
                    text: reply.message || "unable to print file",
                    heading: "ERROR!",
                    icon: "error",
                    showHideTransition: "fade",
                    allowToastClose: true,
                    hideAfter: 5000,
                    stack: 5,
                    position: "top-center"
                });
            }
        })
        .catch(function(err) {
            console.log(err);
            $.toast({
                text: "failed to send file",
                heading: "ERROR!",
                icon: "error",
                showHideTransition: "fade",
                allowToastClose: true,
                hideAfter: 5000,
                stack: 5,
                position: "top-center"
            });
        });
}


document.addEventListener("DOMContentLoaded", function(event) {
    let pbutton = document.getElementById("print-btn");
    pbutton.addEventListener("click", function(event) {
        uploadFile();
    });
});
