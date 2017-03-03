var gulp = require('gulp'),
    concat = require('gulp-concat'),
    rename = require('gulp-rename'),
    uglify = require('gulp-uglify'),
    jsdoc = require('gulp-jsdoc3');

gulp.task('js', function () {
    return gulp.src(['./src/**/*.js'])
        .pipe(concat('SignerDesktopClient.js'))
        .pipe(gulp.dest('dist'))
        .pipe(rename('SignerDesktopClient.min.js'))
        .pipe(uglify())
        .pipe(gulp.dest('dist'));
});

gulp.task('doc', function (cb) {

    var config = require('./jsdoc.json');

    gulp.src(['README.md', './src/**/*.js'], { read: false })
        .pipe(jsdoc(config, cb));
});

gulp.task('watch', function() {
    gulp.watch('src/js/**/*.js', ['js', 'doc']);
    gulp.watch('README.md', ['doc']);
});

gulp.task('default', ['js', 'doc', 'watch'], function () {

});