function uploadFile() {
    let formData = new FormData();

    formData.append("file", document.getElementById("upload-file").files[0]);
    formData.append("copies", document.getElementById("copies").value);
    formData.append("sides", document.getElementById("sides").value);
    formData.append("media", document.getElementById("media").value);
    formData.append("color", document.getElementById("color").value);

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
                document.getElementById("copies").value = 1;
                document.getElementById("sides").selectedIndex = null
                document.getElementById("media").selectedIndex = null
                document.getElementById("color").selectedIndex = null
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
